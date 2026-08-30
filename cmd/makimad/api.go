package main

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/serve"
)

// The daemon's answer to "what are you doing", and the handful of things it
// will be told to do. Everything here is read or written under n.mu, because
// these run on HTTP goroutines while the poll loop is rewriting the same
// fields.

var _ localapi.Backend = (*node)(nil)

// Status reports the daemon's whole view of itself.
func (n *node) Status() localapi.Status {
	n.mu.Lock()
	f := n.file
	iface := n.ifaceName
	if n.engine != nil {
		iface = n.engine.Name()
	}
	addr, _ := f.Self.Addr()

	st := localapi.Status{
		Version: version,
		Node: localapi.NodeInfo{
			Name:             f.Self.Name,
			Address:          addr,
			Interface:        iface,
			Services:         f.AdvertisedServices(),
			AdvertisedRoutes: f.AdvertiseRoutes,
			AdvertisesExit:   f.AdvertiseExit,
		},
		Managed:  f.Managed(),
		Server:   f.LoginServer,
		Domain:   f.Domain,
		ExitNode: f.ExitNode,
		Since:    n.startedAt,
	}

	// The approved half comes back in our own netmap entry rather than from
	// anything local, which is the point: what this node asked for and what
	// the mesh agreed to are different questions.
	for _, r := range f.Self.AllowedIPs {
		if netmap.IsDefaultHalf(r) {
			st.Node.ExitApproved = true
			continue
		}
		st.Node.ApprovedRoutes = append(st.Node.ApprovedRoutes, r)
	}

	peers := make([]localapi.PeerInfo, 0, len(f.Peers))
	for _, p := range f.Peers {
		pa, _ := p.Addr()
		info := localapi.PeerInfo{
			Name:     p.Name,
			Address:  pa,
			Online:   p.Online,
			RelayURL: p.RelayURL,
			Services: p.Services,
			ExitNode: p.OffersExit(),
			Path:     "no path",
		}
		for _, r := range p.AllowedIPs {
			if !netmap.IsDefaultHalf(r) {
				info.Routes = append(info.Routes, r)
			}
		}
		peers = append(peers, info)
	}
	n.mu.Unlock()

	// Path state lives in the socket, not the config, and is keyed by node key
	// rather than name.
	if n.sock != nil {
		byKey := make(map[string]int, len(peers))
		n.mu.Lock()
		for i, p := range n.file.Peers {
			byKey[p.Key.String()] = i
		}
		n.mu.Unlock()

		for _, s := range n.sock.Status() {
			i, ok := byKey[s.NodeKey.String()]
			if !ok || i >= len(peers) {
				continue
			}
			peers[i].Direct = s.DirectOK
			peers[i].Latency = s.Latency
			switch {
			case s.DirectOK:
				peers[i].Path = "direct " + s.Direct.String()
			case s.RelayURL != "":
				peers[i].Path = "relay " + s.RelayURL
			}
		}
		st.Relay = localapi.RelayInfo{URL: n.sock.RelayURL(), Connected: n.sock.RelayConnected()}
	}
	st.Peers = peers

	if n.serve != nil {
		st.Services = n.serve.Status()
	}
	if n.firewall != nil {
		st.Firewall = n.firewall.Status()
	}
	if n.filter != nil {
		st.Filtering = n.filter.Active()
		st.Dropped = n.filter.Dropped()
	}
	st.DNSActive = n.dns != nil
	return st
}

// Diagnose answers "why is this not working" in the order the answers usually
// turn out to be.
//
// Deliberately ordered by how often each thing is the actual cause rather than
// by layer. Somebody running this has already concluded the network is broken;
// the fastest way to help is to check the things that merely look like a
// broken network first.
func (n *node) Diagnose() localapi.Diagnosis {
	var d localapi.Diagnosis
	add := func(c localapi.Check) { d.Checks = append(d.Checks, c) }

	n.mu.Lock()
	f := n.file
	iface := n.ifaceName
	if n.engine != nil {
		iface = n.engine.Name()
	}
	addr, addrErr := f.Self.Addr()
	lastPoll, pollErr := n.lastPoll, n.lastPollErr
	services := append([]serve.Service(nil), f.Services...)
	peers := append([]netmap.Node(nil), f.Peers...)
	exitNode := f.ExitNode
	managed := f.Managed()
	domain := f.Domain
	n.mu.Unlock()

	// 1. The tunnel itself.
	if addrErr != nil {
		add(localapi.Check{
			Name:   "Tunnel",
			Detail: "this node has no mesh address yet, so nothing can reach it",
			Fix:    "makima-server authkey   # then: sudo makima join -server ... -authkey ...",
		})
	} else {
		add(localapi.Check{
			Name:   "Tunnel",
			OK:     true,
			Detail: fmt.Sprintf("%s is up on %s", iface, addr),
		})
	}

	// 2. The host firewall — the single most common reason a home server is
	// unreachable after the tunnel is genuinely working.
	if n.firewall != nil {
		r := n.firewall.Status()
		add(localapi.Check{
			Name:    "Host firewall",
			OK:      r.OK(),
			Detail:  r.Detail,
			Fix:     firewallFix(r),
			Warning: false,
		})
	}

	// 3. Published services whose target is not actually running. The second
	// most common cause, and the one that looks most like a network fault from
	// the far end: the connection is accepted and then nothing answers.
	if n.serve != nil {
		for _, s := range n.serve.Status() {
			switch {
			case s.Error != "":
				add(localapi.Check{
					Name:   "Service " + s.Service.String(),
					Detail: "could not listen: " + s.Error,
				})
			case !s.TargetUp:
				add(localapi.Check{
					Name: "Service " + s.Service.String(),
					Detail: fmt.Sprintf(
						"published, but nothing is listening on %s — peers will connect and get nothing", s.Target),
					Fix: "start the service, or check it is on the port you think it is",
				})
			default:
				add(localapi.Check{
					Name:   "Service " + s.Service.String(),
					OK:     true,
					Detail: fmt.Sprintf("listening on %s, forwarding to %s", s.Address, s.Target),
				})
			}
		}
	}
	if len(services) == 0 {
		add(localapi.Check{
			Name:    "Published services",
			OK:      true,
			Warning: true,
			Detail:  "nothing is published from this machine",
			Fix:     "sudo makima serve 11434   # publishes a local port on the mesh",
		})
	}

	// 4. The control plane.
	if managed {
		switch {
		case pollErr != nil:
			add(localapi.Check{
				Name:   "Control plane",
				Detail: "last netmap poll failed: " + pollErr.Error(),
				Fix:    "check the control server is running and reachable",
			})
		case lastPoll.IsZero():
			add(localapi.Check{
				Name:    "Control plane",
				Warning: true,
				Detail:  "no netmap received yet",
			})
		default:
			add(localapi.Check{
				Name:   "Control plane",
				OK:     true,
				Detail: fmt.Sprintf("netmap current, last heard %s ago", time.Since(lastPoll).Round(time.Second)),
			})
		}
	}

	// 5. Paths to peers.
	if n.sock != nil && len(peers) > 0 {
		direct, relayed, stranded := 0, 0, 0
		for _, s := range n.sock.Status() {
			switch {
			case s.DirectOK:
				direct++
			case s.RelayURL != "":
				relayed++
			default:
				stranded++
			}
		}
		switch {
		case stranded > 0:
			add(localapi.Check{
				Name: "Paths to peers",
				Detail: fmt.Sprintf(
					"%d peer(s) have no path at all: no direct route and no relay", stranded),
				Fix: "makima-server relay add -url <host>:3478 -key <its key>",
			})
		case relayed > 0 && direct == 0:
			add(localapi.Check{
				Name:    "Paths to peers",
				OK:      true,
				Warning: true,
				Detail: fmt.Sprintf(
					"all %d peer(s) are going through the relay; it works, but it is the slow path", relayed),
			})
		default:
			add(localapi.Check{
				Name:   "Paths to peers",
				OK:     true,
				Detail: fmt.Sprintf("%d direct, %d relayed", direct, relayed),
			})
		}
	}

	// 6. Mesh names.
	if domain != "" {
		add(localapi.Check{
			Name:    "Mesh names",
			OK:      n.dns != nil,
			Warning: n.dns == nil,
			Detail: map[bool]string{
				true:  fmt.Sprintf("*.%s resolves on this machine", domain),
				false: fmt.Sprintf("*.%s is enabled on the mesh but this node's resolver is not running", domain),
			}[n.dns != nil],
			Fix: "check nothing else holds port 53 on the mesh address",
		})
	}

	// 7. An exit node that was selected but is not usable.
	if exitNode != "" {
		peer, found := findPeer(peers, exitNode)
		switch {
		case !found:
			add(localapi.Check{
				Name:   "Exit node",
				Detail: fmt.Sprintf("%q is selected but is not in this node's netmap", exitNode),
				Fix:    "sudo makima set -exit-node \"\"   # or check the name",
			})
		case !peer.OffersExit():
			add(localapi.Check{
				Name:   "Exit node",
				Detail: fmt.Sprintf("%s is selected but has not been approved as an exit node", exitNode),
				Fix:    fmt.Sprintf("makima-server routes approve -name %s -exit", exitNode),
			})
		default:
			add(localapi.Check{
				Name:   "Exit node",
				OK:     true,
				Detail: "routing all traffic through " + exitNode,
			})
		}
	}

	return d
}

func firewallFix(r netcfg.Report) string {
	if r.OK() {
		return ""
	}
	if r.Automatic {
		return "sudo makima firewall allow"
	}
	return r.Manual
}

// AddService publishes a local port on the mesh.
func (n *node) AddService(s serve.Service) error {
	if err := s.Validate(); err != nil {
		return err
	}

	n.mu.Lock()
	for _, existing := range n.file.Services {
		if existing.Port == s.Port {
			n.mu.Unlock()
			return fmt.Errorf("port %d is already published, forwarding to %s", s.Port, existing.Target)
		}
	}
	n.file.Services = append(n.file.Services, s)
	n.mu.Unlock()

	return n.servicesChanged()
}

// RemoveService withdraws one.
func (n *node) RemoveService(port uint16) error {
	n.mu.Lock()
	kept := make([]serve.Service, 0, len(n.file.Services))
	found := false
	for _, s := range n.file.Services {
		if s.Port == port {
			found = true
			continue
		}
		kept = append(kept, s)
	}
	if !found {
		n.mu.Unlock()
		return fmt.Errorf("nothing is published on port %d", port)
	}
	n.file.Services = kept
	n.mu.Unlock()

	return n.servicesChanged()
}

// servicesChanged persists the list, rebinds the listeners, and tells the mesh.
//
// The re-registration is what makes a newly published port show up in every
// other node's UI within a second rather than at the next poll heartbeat.
func (n *node) servicesChanged() error {
	n.mu.Lock()
	addr, _ := n.file.Self.Addr()
	services := append([]serve.Service(nil), n.file.Services...)
	err := conf.Save(n.cfgPath, n.file)
	n.mu.Unlock()

	if err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	if n.serve != nil {
		n.serve.Apply(addr, services)
	}
	if n.client != nil {
		go n.reregister()
	}
	return nil
}

// reregister republishes this node's advertisements out of band.
func (n *node) reregister() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := n.register(ctx); err != nil {
		logf("could not republish to the control server: %v", err)
	}
}

// SetExitNode routes this machine's traffic through a peer, or stops.
func (n *node) SetExitNode(name string) error {
	n.mu.Lock()
	if name != "" {
		if _, ok := findPeer(n.file.Peers, name); !ok {
			n.mu.Unlock()
			return fmt.Errorf("no peer named %q", name)
		}
	}
	n.file.ExitNode = name
	m := n.netMapLocked()
	err := conf.Save(n.cfgPath, n.file)
	n.mu.Unlock()

	if err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	n.applyExitNode(m)
	return nil
}

// AllowFirewall makes the host firewall accept tunnel traffic.
func (n *node) AllowFirewall() (netcfg.Report, error) {
	if n.firewall == nil {
		return netcfg.Report{}, fmt.Errorf("no firewall control on this platform")
	}
	return n.firewall.Allow()
}

// meshAddr is the node's own address, or the zero value before one is assigned.
func (n *node) meshAddr() netip.Addr {
	n.mu.Lock()
	defer n.mu.Unlock()
	a, _ := n.file.Self.Addr()
	return a
}
