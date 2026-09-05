package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
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
		Managed:    f.Managed(),
		Serverless: f.Serverless,
		Server:     f.LoginServer,
		Domain:     f.Domain,
		ExitNode:   f.ExitNode,
		Since:      n.startedAt,
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

	if n.inbox != nil {
		dir, active, received := n.inbox.Status()
		st.Inbox = localapi.InboxInfo{Dir: dir, Active: active, Received: received}
	}

	if n.ssh != nil {
		addr, active, fingerprint, sessions := n.ssh.Status()
		st.SSH = localapi.SSHInfo{Active: active, Fingerprint: fingerprint, Sessions: sessions}
		if active {
			st.SSH.Addr = addr.String()
		}

		n.mu.Lock()
		st.SSH.Sources = append([]string(nil), n.file.SSHKeys...)
		userName := n.file.SSHUser
		n.mu.Unlock()

		if u, err := resolveSSHUser(userName); err == nil {
			st.SSH.User = u.Name
		}
		if n.sshKeys != nil {
			count, _, keyErr := n.sshKeys.Status()
			st.SSH.Keys = count
			if keyErr != nil {
				st.SSH.KeyError = keyErr.Error()
			}
		}
	}

	// An open pairing window is the one piece of state a person is likely to
	// be actively waiting on, so status reports it rather than making them
	// remember whether they left one open.
	if n.sock != nil && n.sock.PairingOpen() {
		if address, expires, err := n.pairAddressString(); err == nil {
			st.Pairing = &localapi.PairingState{Address: address, Expires: expires}
		}
	}
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
			Detail: "this device has no address on the network yet, so nothing can reach it",
			Fix:    "makima join <invite>   # get an invite from the device that started the network: makima invite",
		})
	} else {
		add(localapi.Check{
			Name:   "Tunnel",
			OK:     true,
			Detail: fmt.Sprintf("%s is up on %s", iface, addr),
		})
	}

	// 2. Another VPN on the same addresses. Tailscale hands out the same
	// 100.64.0.0/10 that makima does, and while it runs it claims the whole
	// range for itself: on Linux with a firewall rule that drops every packet
	// from that range not arriving on its own interface, on macOS with a
	// route. Either way the symptom is a tunnel that is up, addresses that
	// are right, and nothing getting through — which is exactly what a
	// person who is trying makima instead of Tailscale will see first.
	if others := otherCGNATInterfaces(listInterfaces(), iface); len(others) > 0 {
		add(localapi.Check{
			Name: "Another VPN",
			Detail: fmt.Sprintf(
				"%s also uses makima's address range (100.64.0.0/10) — that is Tailscale's range too, and while both run, the other one can swallow makima's traffic",
				strings.Join(others, ", ")),
			Fix: "quit Tailscale (or whichever VPN that is) while using makima",
		})
	}

	// 3. The host firewall — the single most common reason a home server is
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

	// 4. Published services whose target is not actually running. The second
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
			Fix:     "makima allow 11434   # publishes a local port on the network",
		})
	}

	// 5. The network's server.
	if managed {
		switch {
		case pollErr != nil:
			add(localapi.Check{
				Name:   "Network server",
				Detail: "cannot reach the device holding the network: " + pollErr.Error(),
				Fix:    "check that device is on and reachable from here — new devices cannot join until it is, but existing ones keep working",
			})
		case lastPoll.IsZero():
			add(localapi.Check{
				Name:    "Network server",
				Warning: true,
				Detail:  "waiting for the first update from the device holding the network",
			})
		default:
			add(localapi.Check{
				Name:   "Network server",
				OK:     true,
				Detail: fmt.Sprintf("in touch, last heard %s ago", time.Since(lastPoll).Round(time.Second)),
			})
		}
	}

	// 6. Paths to peers.
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

	// 7. Names.
	if domain != "" {
		add(localapi.Check{
			Name:    "Names",
			OK:      n.dns != nil,
			Warning: n.dns == nil,
			Detail: map[bool]string{
				true:  fmt.Sprintf("*.%s resolves on this machine", domain),
				false: fmt.Sprintf("*.%s is on for the network but this device's resolver is not running", domain),
			}[n.dns != nil],
			Fix: "check nothing else holds port 53 on this device's makima address",
		})
	}

	// 8. An exit node that was selected but is not usable.
	if exitNode != "" {
		peer, found := findPeer(peers, exitNode)
		switch {
		case !found:
			add(localapi.Check{
				Name:   "Exit node",
				Detail: fmt.Sprintf("%q is selected but is not on this network", exitNode),
				Fix:    "makima set -exit-node \"\"   # or check the name",
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
		return "makima firewall allow"
	}
	return r.Manual
}

// ifaceAddrs is one interface and the addresses on it, as much as the
// address-range check needs — and a shape a test can build by hand.
type ifaceAddrs struct {
	name  string
	addrs []netip.Prefix
}

// listInterfaces reads the machine's interfaces and their addresses.
func listInterfaces() []ifaceAddrs {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]ifaceAddrs, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		entry := ifaceAddrs{name: iface.Name}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			entry.addrs = append(entry.addrs, netip.PrefixFrom(addr.Unmap(), ones))
		}
		out = append(out, entry)
	}
	return out
}

// otherCGNATInterfaces names every interface other than makima's own that
// holds an address in makima's range. One name per interface, in the order
// the system lists them.
func otherCGNATInterfaces(ifaces []ifaceAddrs, self string) []string {
	var out []string
	for _, iface := range ifaces {
		if iface.name == self {
			continue
		}
		for _, p := range iface.addrs {
			if netcfg.CGNATRange.Contains(p.Addr()) {
				out = append(out, iface.name)
				break
			}
		}
	}
	return out
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
	// Publishing a port on purpose withdraws any standing refusal of it,
	// otherwise denying something once would quietly veto every later attempt
	// to publish it and there would be nothing on screen explaining why.
	n.file.DeniedPorts = dropPort(n.file.DeniedPorts, s.Port)
	n.mu.Unlock()

	return n.servicesChanged()
}

func dropPort(ports []uint16, p uint16) []uint16 {
	out := ports[:0]
	for _, v := range ports {
		if v != p {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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

	// An automatically published port counts as published: it is on the mesh,
	// somebody can see it, and asking for it to stop is a reasonable thing to
	// do. Refusing because it is not in the explicit list would be an
	// implementation detail leaking out as an error message.
	auto := false
	for _, s := range n.autoServices {
		if s.Port == port {
			auto = true
			break
		}
	}
	if !found && !auto {
		n.mu.Unlock()
		return fmt.Errorf("nothing is published on port %d", port)
	}

	n.file.Services = kept
	// Recorded, not merely withdrawn. The scanner runs again in five seconds
	// and would republish anything still listening, so without this "deny"
	// would mean "for five seconds".
	if !containsPort(n.file.DeniedPorts, port) {
		n.file.DeniedPorts = append(n.file.DeniedPorts, port)
	}
	for i, s := range n.autoServices {
		if s.Port == port {
			n.autoServices = append(n.autoServices[:i:i], n.autoServices[i+1:]...)
			break
		}
	}
	n.mu.Unlock()

	return n.servicesChanged()
}

func containsPort(ports []uint16, p uint16) bool {
	for _, v := range ports {
		if v == p {
			return true
		}
	}
	return false
}

// servicesChanged persists the list, rebinds the listeners, and tells the mesh.
//
// The re-registration is what makes a newly published port show up in every
// other node's UI within a second rather than at the next poll heartbeat.
func (n *node) servicesChanged() error {
	n.mu.Lock()
	err := conf.Save(n.cfgPath, n.file)
	n.mu.Unlock()

	if err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	if n.serve != nil {
		// The union, not just the explicit list: rebinding to file.Services
		// alone would tear down every automatically published port every time
		// somebody published one by hand.
		n.applyServices()
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

// SetAdvertiseExit offers this machine as an exit node, or withdraws the
// offer, and tells the network at once.
//
// Live, like SetExitNode, so that a switch in the app is a switch and not a
// restart. The offer is accepted by the server as it arrives; from then on
// any other device can pick this one by name.
func (n *node) SetAdvertiseExit(on bool) error {
	n.mu.Lock()
	n.file.AdvertiseExit = on
	err := conf.Save(n.cfgPath, n.file)
	n.mu.Unlock()

	if err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	if n.client == nil {
		return fmt.Errorf("this machine has no network server to offer itself to")
	}
	// Synchronous, with the same patience a registration usually gets: the
	// caller is a person who just flipped a switch, and the next status they
	// read should already say the offer was accepted.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.register(ctx); err != nil {
		return fmt.Errorf("the offer is saved, but the network could not be told yet: %w", err)
	}
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

// OpenPairing publishes a pairing address and starts answering knocks on it.
func (n *node) OpenPairing(seconds int) (localapi.PairingState, error) {
	ttl := time.Duration(seconds) * time.Second
	address, expires, err := n.openPairing(ttl)
	if err != nil {
		return localapi.PairingState{}, err
	}
	return localapi.PairingState{Address: address, Expires: expires}, nil
}

// ClosePairing stops answering knocks.
func (n *node) ClosePairing() { n.closePairing() }

// Pair knocks on another machine's published address.
func (n *node) Pair(ctx context.Context, address string) (localapi.PairedResult, error) {
	peer, err := n.knock(ctx, address)
	if err != nil {
		return localapi.PairedResult{}, err
	}
	addr, _ := peer.Addr()
	return localapi.PairedResult{Name: peer.Name, Address: addr}, nil
}

// Ping probes one peer by name and reports the path to it.
//
// The probe is fired and the path read immediately afterwards, without waiting
// for a reply. That is deliberate: a pong may take a round trip to arrive, and
// blocking here would make one slow peer stall the socket the caller is asking
// through. The caller polls, which is also what makes `-until-direct` a loop
// rather than a single long request.
func (n *node) Ping(name string) (localapi.Ping, error) {
	n.mu.Lock()
	var peer netmap.Node
	found := false
	bare := strings.TrimSuffix(name, "."+n.file.Domain)
	for _, p := range n.file.Peers {
		if p.Name == bare || p.Name == name {
			peer, found = p, true
			break
		}
	}
	known := make([]string, 0, len(n.file.Peers))
	for _, p := range n.file.Peers {
		known = append(known, p.Name)
	}
	n.mu.Unlock()

	if !found {
		if len(known) == 0 {
			return localapi.Ping{}, fmt.Errorf("no peer named %q — this machine has no peers yet", name)
		}
		return localapi.Ping{}, fmt.Errorf("no peer named %q — this machine can see %s", name, strings.Join(known, ", "))
	}

	addr, _ := peer.Addr()
	out := localapi.Ping{Name: peer.Name, Address: addr, Path: "no path", RelayURL: peer.RelayURL}

	if n.sock == nil {
		// A static mesh has one fixed path per peer and nothing to select
		// between, so there is no probing to do and nothing to wait for.
		if len(peer.Endpoints) > 0 {
			out.Direct = true
			out.Path = "direct " + peer.Endpoints[0].String()
		}
		return out, nil
	}

	n.sock.ProbeNow(peer.Key)

	st, ok := n.sock.PeerStatus(peer.Key)
	if !ok {
		return out, nil
	}

	out.Direct = st.DirectOK
	out.Latency = st.Latency
	out.RelayLatency = st.RelayLatency
	out.Candidates = st.Candidates
	if st.RelayURL != "" {
		out.RelayURL = st.RelayURL
	}
	switch {
	case st.DirectOK:
		out.Path = "direct " + st.Direct.String()
	case st.RelayURL != "":
		out.Path = "relay " + st.RelayURL
	}
	return out, nil
}
