package main

import (
	"context"
	"log"
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

// watchLocalPorts publishes this machine's loopback-only services on the mesh,
// and withdraws them again when they stop.
//
// This is the difference between "makima works" and "makima needs no
// instructions". A service on 127.0.0.1 is unreachable through the tunnel no
// matter how healthy the mesh is, and the fix — publish the port — is a step
// you can only take if you already understand why it is necessary. Which means
// the people most likely to need it are the least likely to know it exists.
//
// The rule this encodes is that your own mesh is as trusted as your own
// machine. That is the right default for the three computers one person owns,
// and it is stated in the daemon's startup log rather than left to be
// discovered, because it stops being right the moment somebody else's laptop
// joins.
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

	discovered := localports.Forwardable(found, exclude)

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
