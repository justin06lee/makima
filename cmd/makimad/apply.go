package main

import (
	"context"
	"log"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/dnsserver"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/portmap"
)

// rejection records a peer that failed verification.
type rejection struct {
	name string
	err  error
}

// verifyPeers drops peers whose key signature does not check out.
//
// This is the whole point of the network lock, and the reason it is enforced
// here rather than on the server. The control plane is the thing being
// defended against: it is trusted to say who *should* be in the mesh, and this
// check means it cannot be trusted to say who *is*. A server that invents a
// peer has to produce a signature over a key it does not hold, and the
// invention is rejected by every node independently.
//
// With no lock configured every peer is admitted, which is what a mesh that
// has not opted in has always done.
func verifyPeers(resp *control.MapResponse) ([]netmap.Node, []rejection) {
	if resp.Lock == nil || !resp.Lock.Enabled {
		return resp.Peers, nil
	}

	lock := &control.Lock{Enabled: true, TrustedKeys: resp.Lock.TrustedKeys}

	kept := make([]netmap.Node, 0, len(resp.Peers))
	var rejected []rejection

	for _, p := range resp.Peers {
		if err := lock.VerifyNodeKey(p.ID, p.Key, p.KeySignature); err != nil {
			rejected = append(rejected, rejection{name: p.Name, err: err})
			continue
		}
		kept = append(kept, p)
	}
	return kept, rejected
}

// applyDNS starts, updates, or stops the mesh resolver.
//
// The resolver binds the node's own mesh address, so it cannot start before
// the interface has one — which is why this is driven by netmap application
// rather than by startup.
func (n *node) applyDNS(ctx context.Context, m *netmap.NetMap) {
	if !m.DNS.Enabled || m.Domain == "" {
		n.stopDNS()
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
	}

	n.dns.SetRecords(m.Domain, m.Self, m.Peers)

	if err := n.resolver.Set(m.Domain, addr); err != nil {
		log.Printf("warning: %v", err)
	}
}

func (n *node) stopDNS() {
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

// applyExitNode reconciles both halves of exit-node behaviour.
//
// Advertising and using are independent: a machine can be an exit node for
// others, use one itself, both, or neither.
func (n *node) applyExitNode(m *netmap.NetMap) {
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
	if n.advertiser == nil {
		n.advertiser = netcfg.NewAdvertiser(n.engine.Name())
	}

	if approved == n.advertiser.Enabled() {
		return
	}
	if approved {
		if err := n.advertiser.Enable(); err != nil {
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
func (n *node) applyUseExit(m *netmap.NetMap) {
	if n.exitClient == nil {
		n.exitClient = netcfg.NewExitClient(n.engine.Name())
	}

	want := n.file.ExitNode
	if want == "" {
		if _, active := n.exitClient.Active(); active {
			if err := n.exitClient.Stop(); err != nil {
				log.Printf("warning: could not restore normal routing: %v", err)
				return
			}
			log.Print("no longer using an exit node")
		}
		return
	}

	peer, ok := findPeer(m.Peers, want)
	if !ok {
		log.Printf("exit node %q is not in this node's netmap; routing normally", want)
		return
	}
	if !peer.OffersExit() {
		log.Printf("%s is not an approved exit node; routing normally", want)
		return
	}

	addr, err := peer.Addr()
	if err != nil {
		return
	}
	if current, active := n.exitClient.Active(); active && current == addr {
		return
	}

	gw, err := portmap.Gateway()
	if err != nil {
		log.Printf("cannot use an exit node: %v", err)
		return
	}

	if err := n.exitClient.Use(addr, peer.Endpoints, gw); err != nil {
		log.Printf("cannot use exit node %s: %v", want, err)
		return
	}
	log.Printf("routing all traffic through %s (%s)", peer.Name, addr)
}

func findPeer(peers []netmap.Node, name string) (netmap.Node, bool) {
	for _, p := range peers {
		if p.Name == name {
			return p, true
		}
	}
	return netmap.Node{}, false
}
