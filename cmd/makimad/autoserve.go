package main

import (
	"context"
	"log"
	"sort"
	"time"

	"github.com/justin06lee/makima/internal/localports"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/serve"
)

// autoServeInterval is how often the daemon looks for new local services.
//
// Short enough that starting a dev server and switching to the laptop feels
// immediate, long enough that the scan is invisible. On Linux it is two small
// file reads; on macOS it is one lsof, which is why it is not a second.
const autoServeInterval = 5 * time.Second

// A port is published once it has been listening for publishAfter scans in a
// row, and withdrawn once it has been gone for withdrawAfter.
//
// Every change to what a node publishes reaches every other node as a new
// netmap, so a scanner that reports each scan as it finds it turns a dev
// server restarting on save into a mesh-wide update every few seconds. A
// service worth reaching from another machine is one that stays up for ten
// seconds; one that blinks out for a moment while it restarts is still there.
const (
	publishAfter  = 2
	withdrawAfter = 3
)

// dynamicPorts is where the IANA dynamic range starts. A listener up there is
// almost always something's private helper — a language server, a debugger,
// a tor control port — bound to whatever the kernel handed it, gone and back
// on another number next time. Publishing those is noise, and churn.
// `makima serve` still publishes one on purpose.
const dynamicPorts = 49152

// settler turns a stream of scans into the set of ports steady enough to
// publish. The first scan is taken as it is: whatever was already running
// when the daemon started has been up for a while.
type settler struct {
	primed bool
	seen   map[uint16]int
	gone   map[uint16]int
	up     map[uint16]localports.Listener
}

func newSettler() *settler {
	return &settler{
		seen: make(map[uint16]int),
		gone: make(map[uint16]int),
		up:   make(map[uint16]localports.Listener),
	}
}

// observe records one scan and returns what should be published now, in port
// order.
func (s *settler) observe(found []localports.Listener) []localports.Listener {
	present := make(map[uint16]bool, len(found))
	for _, l := range found {
		present[l.Port] = true
		delete(s.gone, l.Port)
		s.seen[l.Port] = min(s.seen[l.Port]+1, publishAfter)
		if _, ok := s.up[l.Port]; ok || !s.primed || s.seen[l.Port] >= publishAfter {
			s.up[l.Port] = l
		}
	}
	for p := range s.seen {
		if !present[p] {
			delete(s.seen, p)
		}
	}
	for p := range s.up {
		if present[p] {
			continue
		}
		s.gone[p]++
		if s.gone[p] >= withdrawAfter {
			delete(s.up, p)
			delete(s.gone, p)
		}
	}
	s.primed = true

	out := make([]localports.Listener, 0, len(s.up))
	for _, l := range s.up {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// watchLocalPorts publishes this machine's loopback-only services on the mesh,
// and withdraws them again when they stop.
//
// A service on 127.0.0.1 is unreachable through the tunnel no matter how
// healthy the mesh is, and the fix — publish the port — is a step you can only
// take if you already know it is necessary.
//
// The rule this encodes is that your own mesh is as trusted as your own
// machine. Right for the computers one person owns, wrong the moment somebody
// else's laptop joins, so the daemon says so at startup.
func (n *node) watchLocalPorts(ctx context.Context) {
	t := time.NewTicker(autoServeInterval)
	defer t.Stop()

	n.refreshAutoServices()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.refreshAutoServices()
		}
	}
}

// refreshAutoServices rescans and republishes if anything changed.
func (n *node) refreshAutoServices() {
	found, err := localports.Listening()
	if err != nil {
		// No information is not the same as nothing listening. Withdrawing
		// every automatic service because one scan failed would take a working
		// mesh down over a transient read error.
		if n.verbose {
			log.Printf("auto-serve: %v", err)
		}
		return
	}

	n.mu.Lock()
	exclude := n.reservedPortsLocked()
	explicit := make(map[uint16]bool, len(n.file.Services))
	for _, s := range n.file.Services {
		explicit[s.Port] = true
		exclude[s.Port] = true
	}
	n.mu.Unlock()

	var candidates []localports.Listener
	for _, l := range localports.Forwardable(found, exclude) {
		if l.Port < dynamicPorts {
			candidates = append(candidates, l)
		}
	}
	discovered := n.settled.observe(candidates)

	auto := make([]serve.Service, 0, len(discovered))
	for _, l := range discovered {
		auto = append(auto, serve.Service{
			Name:   l.Name(),
			Port:   l.Port,
			Target: serve.LocalTarget(l.Port),
			Auto:   true,
		})
	}

	n.mu.Lock()
	changed := !sameServices(n.autoServices, auto)
	if changed {
		n.autoServices = auto
	}
	n.mu.Unlock()

	if !changed {
		return
	}

	for _, s := range auto {
		if !explicit[s.Port] {
			log.Printf("auto-serve: %s", s)
		}
	}
	n.applyServices()

	// Peers cannot click a link they were never told about, so a change to
	// what this node offers is worth telling the control plane about now
	// rather than at the next heartbeat.
	if n.client != nil {
		go n.reregister()
	}
}

// applyServices binds the union of what was asked for and what was found.
// applyServices rebinds everything that lives on the mesh address.
func (n *node) applyServices() {
	n.applyInbox()
	n.applySSH(context.Background())
	n.applyPublishedPorts()
}

func (n *node) applyPublishedPorts() {
	n.mu.Lock()
	addr, err := n.file.Self.Addr()
	svcs := n.effectiveServicesLocked()
	n.mu.Unlock()

	if err != nil {
		return
	}
	n.serve.Apply(addr, svcs)
}

// effectiveServicesLocked is every service this node publishes.
//
// Explicit first, so that if somebody has published a port deliberately — with
// a name, or forwarding to a different local port than the mesh one — their
// version is the one that binds and the scanner's guess is discarded.
func (n *node) effectiveServicesLocked() []serve.Service {
	out := make([]serve.Service, 0, len(n.file.Services)+len(n.autoServices))
	seen := make(map[uint16]bool, len(n.file.Services))

	for _, s := range n.file.Services {
		out = append(out, s)
		seen[s.Port] = true
	}
	if !n.autoServe {
		return out
	}
	for _, s := range n.autoServices {
		if !seen[s.Port] {
			out = append(out, s)
		}
	}
	return out
}

// advertisedServicesLocked is what peers are told this node offers.
func (n *node) advertisedServicesLocked() []netmap.Service {
	svcs := n.effectiveServicesLocked()
	if len(svcs) == 0 {
		return nil
	}
	out := make([]netmap.Service, 0, len(svcs))
	for _, s := range svcs {
		out = append(out, netmap.Service{
			Name:   s.Name,
			Port:   s.Port,
			Scheme: netmap.GuessScheme(s.Port),
		})
	}
	return out
}

// reservedPortsLocked are the loopback ports the daemon must not publish.
//
// Two sources. Ports somebody denied, which have to survive the next scan or
// "deny" would mean "for five seconds". And the web UI, which with -ui-write
// can change this node's settings — putting that on the mesh would hand
// control of the machine to anything that can reach the address, which is the
// opposite of the guarantee its loopback default exists to make.
func (n *node) reservedPortsLocked() map[uint16]bool {
	out := make(map[uint16]bool, len(n.file.DeniedPorts)+1)
	if n.uiPort != 0 {
		out[n.uiPort] = true
	}
	for _, p := range n.file.DeniedPorts {
		out[p] = true
	}
	return out
}

func sameServices(a, b []serve.Service) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
