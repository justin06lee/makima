package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"runtime"

	"github.com/justin06lee/makima/internal/bypass"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/dnsserver"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/portmap"
)

// rejection records a peer that failed verification.
type rejection struct {
	name string
	err  error
}

// verifyPeers drops peers whose key signature does not check out, against
// the network lock as this node holds it.
//
// This is the whole point of the network lock, and the reason it is enforced
// here rather than on the server. The control plane is the thing being
// defended against: it is trusted to say who *should* be in the mesh, and this
// check means it cannot be trusted to say who *is*. A server that invents a
// peer has to produce a signature over a key it does not hold, and the
// invention is rejected by every node independently.
//
// Which keys to check against is not the server's to say either. The node
// keeps its own copy of the lock (pin) and moves it only along versions
// signed by a key it already trusts; a server that stops sending the lock,
// sends it switched off, or sends a key of its own changes nothing here.
// Returns the pin as it stands after this netmap.
//
// network is the key of the control plane this node joined: only versions
// of that network's lock are followed, not ones the same signing key made
// for another.
//
// With no lock ever seen every peer is admitted, which is what a mesh that
// has not opted in has always done. A server whose lock predates signed
// versions is believed as it always was, since it offers nothing to pin.
func verifyPeers(resp *control.MapResponse, network key.Public, pin *netmap.LockPin) ([]netmap.Node, []rejection, *netmap.LockPin, error) {
	var chainErr error
	if resp.Lock != nil && len(resp.Lock.Chain) > 0 {
		pin, chainErr = control.AdvanceLock(network, pin, resp.Lock.Chain)
	}

	var check func(p netmap.Node) error
	switch {
	case pin != nil:
		// Only a signature naming this network: a peer signed into another
		// network that trusts the same key is not one of ours.
		check = func(p netmap.Node) error {
			return control.VerifyPinned(network, pin, p.ID, p.Key, p.NetworkSignature)
		}
	case resp.Lock != nil && resp.Lock.Enabled:
		legacy := &control.Lock{Enabled: true, TrustedKeys: resp.Lock.TrustedKeys}
		check = func(p netmap.Node) error {
			return legacy.VerifyLegacy(network, p.ID, p.Key, p.NetworkSignature, p.KeySignature)
		}
	default:
		return resp.Peers, nil, pin, chainErr
	}

	kept := make([]netmap.Node, 0, len(resp.Peers))
	var rejected []rejection
	for _, p := range resp.Peers {
		if err := check(p); err != nil {
			rejected = append(rejected, rejection{name: p.Name, err: err})
			continue
		}
		kept = append(kept, p)
	}
	return kept, rejected, pin, chainErr
}

// applyDNS starts, updates, or stops the mesh resolver.
//
// The resolver binds the node's own mesh address, so it cannot start before
// the interface has one — which is why this is driven by netmap application
// rather than by startup.
func (n *node) applyDNS(ctx context.Context, m *netmap.NetMap) {
	n.dnsMu.Lock()
	defer n.dnsMu.Unlock()

	if !m.DNS.Enabled || m.Domain == "" {
		n.stopDNSLocked()
		return
	}

	addr, err := m.Self.Addr()
	if err != nil {
		return
	}

	if n.dns == nil {
		srv, err := dnsserver.New(addr, log.Default())
		if err != nil {
			// A resolver that cannot bind is not fatal. Port 53 is frequently
			// already taken on a machine running dnsmasq or systemd-resolved
			// on a wildcard, and mesh addressing keeps working without names.
			log.Printf("mesh DNS unavailable: %v", err)
			return
		}
		n.dns = srv
		n.resolver = netcfg.NewResolver(n.engine.Name())
		log.Printf("mesh DNS on %s for *.%s", srv.Addr(), m.Domain)

		// A Mac sends packets for its own utun address into the tunnel
		// rather than looping them back, so it can never ask the resolver
		// above itself. It asks one on loopback instead.
		if runtime.GOOS == "darwin" {
			if lp, err := srv.ListenLoopback(); err != nil {
				log.Printf("warning: %v — mesh names will not resolve on this Mac", err)
			} else {
				log.Printf("mesh DNS for this Mac on %s", lp)
			}
		}
	}

	n.dns.SetRecords(m.Domain, m.Self, m.Peers)

	server := netip.AddrPortFrom(addr, dnsserver.Port)
	if lp := n.dns.Loopback(); lp.IsValid() {
		server = lp
	}
	if err := n.resolver.Set(m.Domain, server); err != nil {
		log.Printf("warning: %v", err)
	}
}

func (n *node) stopDNS() {
	n.dnsMu.Lock()
	defer n.dnsMu.Unlock()
	n.stopDNSLocked()
}

// dnsServer is where makima's own resolver answers on this machine — the
// loopback listener a Mac uses, or the mesh address — or zero when it is
// not running.
func (n *node) dnsServer() netip.AddrPort {
	n.dnsMu.Lock()
	defer n.dnsMu.Unlock()
	if n.dns == nil {
		return netip.AddrPort{}
	}
	if lp := n.dns.Loopback(); lp.IsValid() {
		return lp
	}
	return n.dns.Addr()
}

// dnsActive reports whether the mesh resolver is running.
func (n *node) dnsActive() bool {
	n.dnsMu.Lock()
	defer n.dnsMu.Unlock()
	return n.dns != nil
}

func (n *node) stopDNSLocked() {
	if n.resolver != nil {
		if err := n.resolver.Close(); err != nil {
			log.Printf("warning: could not remove the mesh resolver entry: %v", err)
		}
		n.resolver = nil
	}
	if n.dns != nil {
		n.dns.Close()
		n.dns = nil
	}
}

// exitRouter is the part of netcfg.ExitClient the daemon uses, and
// forwarder the part of netcfg.Advertiser — so a test can stand in for the
// machine's routing table rather than edit it.
type exitRouter interface {
	Use(exitAddr netip.Addr, pins []netip.Addr, gateway netip.Addr) error
	Stop() error
	Active() (netip.Addr, bool)
}

type forwarder interface {
	Enable(self netip.Addr) error
	Disable() error
	Enabled() bool
}

// applyExitNode reconciles both halves of exit-node behaviour.
//
// Advertising and using are independent: a machine can be an exit node for
// others, use one itself, both, or neither.
//
// Called from the poll loop on every netmap and from the local API when
// somebody picks an exit node, so the two are serialised: each half checks
// what is in force and then changes it, and two of those interleaved would
// install a redirect twice or tear down one the other just made.
func (n *node) applyExitNode(m *netmap.NetMap) {
	n.exitMu.Lock()
	defer n.exitMu.Unlock()
	n.applyAdvertise(m)
	n.applyUseExit(m)
}

// applyAdvertise turns on forwarding once the control plane has approved this
// node's offer, and off again when approval is withdrawn.
//
// Keyed on what came back in the netmap rather than on what was asked for.
// Enabling NAT because we *requested* it would let any node turn itself into a
// router, which is exactly what the approval step exists to prevent.
func (n *node) applyAdvertise(m *netmap.NetMap) {
	approved := len(m.Self.AllowedIPs) > 0
	if approved == n.advertiser.Enabled() {
		return
	}
	if approved {
		addr, err := m.Self.Addr()
		if err != nil {
			log.Printf("cannot route for the mesh: %v", err)
			return
		}
		if err := n.advertiser.Enable(addr); err != nil {
			log.Printf("cannot route for the mesh: %v", err)
			return
		}
		log.Printf("routing for the mesh: %v", m.Self.AllowedIPs)
		return
	}
	if err := n.advertiser.Disable(); err != nil {
		log.Printf("warning: %v", err)
		return
	}
	log.Print("no longer routing for the mesh")
}

// applyUseExit redirects this node's own traffic through a peer, or stops.
//
// When the chosen exit node leaves the netmap or loses its approval, normal
// routing comes back. Leaving the redirect in place would send every packet
// into a tunnel that no longer has a peer holding the default route — the
// machine would lose the internet for as long as the setting stayed, with
// nothing on screen saying why.
func (n *node) applyUseExit(m *netmap.NetMap) {
	n.mu.Lock()
	want := n.file.ExitNode
	n.mu.Unlock()

	current, active := n.exitClient.Active()

	if want == "" {
		if active {
			n.stopExit("no longer using an exit node")
		}
		n.noteExit("")
		return
	}

	peer, ok := findPeer(m.Peers, want)
	var refused string
	switch {
	case !ok:
		refused = fmt.Sprintf("exit node %q is not in this node's netmap", want)
	case !peer.OffersExit():
		refused = fmt.Sprintf("%s is not an approved exit node", want)
	}
	addr, err := peer.Addr()
	if refused == "" && err != nil {
		refused = err.Error()
	}
	if refused != "" {
		news := n.noteExit(refused)
		if active {
			n.stopExit(refused + "; routing normally again")
		} else if news {
			log.Printf("%s; routing normally", refused)
		}
		return
	}

	if active && current == addr {
		return
	}

	if !active {
		if err := n.keepTunnelOutOfTunnel(); err != nil {
			if n.noteExit("cannot use exit node " + want + ": " + err.Error()) {
				log.Printf("cannot use exit node %s: %v", want, err)
			}
			return
		}
	}

	// A static mesh has no socket of makima's own to bind, so the exit node's
	// configured addresses are pinned over the old gateway instead.
	var pins []netip.Addr
	var gw netip.Addr
	if n.sock == nil {
		for _, e := range peer.Endpoints {
			pins = append(pins, e.Addr())
		}
		if len(pins) == 0 {
			n.noteExit(fmt.Sprintf("cannot use exit node %s: its real address is unknown", want))
			log.Printf("cannot use exit node %s: its real address is unknown, and redirecting the default route without keeping one reachable would cut off the tunnel itself", want)
			return
		}
		if r, err := portmap.DefaultRoute(); err == nil {
			gw = r.Gateway
		}
		if !gw.IsValid() {
			n.noteExit(fmt.Sprintf("cannot use exit node %s: no default gateway to keep it reachable over", want))
			log.Printf("cannot use exit node %s: no default gateway was found to keep it reachable over", want)
			return
		}
	}

	if err := n.exitClient.Use(addr, pins, gw); err != nil {
		if !active {
			n.releaseTunnel()
		}
		if n.noteExit("cannot use exit node " + want + ": " + err.Error()) {
			log.Printf("cannot use exit node %s: %v", want, err)
		}
		return
	}
	n.noteExit("")
	log.Printf("routing all traffic through %s (%s)", peer.Name, addr)
}

// stopExit restores normal routing, then lets the tunnel's own sockets
// follow the routing table again — in that order, so there is no moment when
// the default route points into the tunnel and the tunnel's packets follow it.
func (n *node) stopExit(why string) {
	if err := n.exitClient.Stop(); err != nil {
		if _, active := n.exitClient.Active(); active {
			// The redirect is still in place, and the next netmap tries
			// again. Keeping the sockets bound meanwhile keeps the tunnel's
			// own traffic out of it.
			log.Printf("warning: could not restore normal routing, will try again: %v", err)
			return
		}
		// Normal routing is back; only a pin could not be removed.
		log.Printf("warning: %v", err)
	}
	n.releaseTunnel()
	log.Print(why)
}

// keepTunnelOutOfTunnel binds the sockets carrying the tunnel — WireGuard's,
// the relay's, the control plane's — to the interface the default route
// leaves by, so that redirecting the default route into the tunnel does not
// take them with it.
func (n *node) keepTunnelOutOfTunnel() error {
	if n.sock == nil {
		return nil // a static mesh pins instead
	}
	ifc, err := defaultInterface()
	if err != nil {
		return err
	}
	if err := n.binder.Bind(ifc); err != nil {
		_ = n.binder.Unbind()
		return fmt.Errorf("keep the tunnel's own traffic on %s: %w", ifc, err)
	}
	n.tunnelMoved()
	return nil
}

// releaseTunnel undoes keepTunnelOutOfTunnel.
func (n *node) releaseTunnel() {
	if _, bound := n.binder.Bound(); !bound {
		return
	}
	if err := n.binder.Unbind(); err != nil {
		log.Printf("warning: %v", err)
	}
	n.tunnelMoved()
}

// rebindExit follows the machine to its new default interface after a
// network change, while an exit node is in use: the socket bound to the Wi-Fi
// that is gone would send nothing.
func (n *node) rebindExit() {
	n.exitMu.Lock()
	defer n.exitMu.Unlock()
	was, bound := n.binder.Bound()
	if !bound {
		return
	}
	ifc, err := defaultInterface()
	if err != nil {
		log.Printf("exit node: %v; keeping the tunnel on %s", err, was)
		return
	}
	if ifc == was {
		return
	}
	if err := n.binder.Bind(ifc); err != nil {
		log.Printf("exit node: could not move the tunnel to %s: %v", ifc, err)
		return
	}
	log.Printf("exit node: the tunnel's own traffic now leaves by %s", ifc)
}

// tunnelMoved re-establishes the connections the tunnel depends on after the
// socket binding changed: the ones already open were set up the other way.
func (n *node) tunnelMoved() {
	if n.sock != nil {
		n.sock.RedialRelay()
	}
	if n.client != nil {
		n.client.DropConnections()
		n.kickPoll()
	}
}

// defaultInterface is the interface the machine's default route leaves by.
// A variable so a test can say where that is.
var defaultInterface = func() (bypass.Interface, error) {
	r, err := portmap.DefaultRoute()
	if err != nil {
		return bypass.Interface{}, fmt.Errorf("no default route to keep the tunnel's own traffic on")
	}
	ifc, err := net.InterfaceByName(r.Interface)
	if err != nil {
		return bypass.Interface{}, fmt.Errorf("the default route's interface %q: %w", r.Interface, err)
	}
	return bypass.Interface{Name: ifc.Name, Index: ifc.Index}, nil
}

// noteExit records why the chosen exit node is not in use, for the doctor,
// and reports whether that is news — so a reason is logged once, not on every
// netmap.
func (n *node) noteExit(why string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	changed := n.exitProblem != why
	n.exitProblem = why
	return changed
}

func findPeer(peers []netmap.Node, name string) (netmap.Node, bool) {
	for _, p := range peers {
		if p.Name == name {
			return p, true
		}
	}
	return netmap.Node{}, false
}
