package main

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/justin06lee/makima/internal/bypass"
	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/netmap"
)

// fakeRoutes stands in for the machine's routing table.
type fakeRoutes struct {
	active   bool
	exit     netip.Addr
	uses     int
	installs int
	stops    int
}

func (f *fakeRoutes) Use(a netip.Addr, pins []netip.Addr, gw netip.Addr) error {
	f.uses++
	if !f.active {
		f.installs++
	}
	f.active, f.exit = true, a
	return nil
}

func (f *fakeRoutes) Stop() error {
	f.stops++
	f.active, f.exit = false, netip.Addr{}
	return nil
}

func (f *fakeRoutes) Active() (netip.Addr, bool) { return f.exit, f.active }

func exitPeer(name, addr string, approved bool) netmap.Node {
	p := netmap.Node{
		Name:      name,
		Addresses: []netip.Prefix{netip.MustParsePrefix(addr + "/32")},
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:41641")},
	}
	if approved {
		p.AllowedIPs = netmap.DefaultHalves
	}
	return p
}

func exitNode(t *testing.T, choice string) (*node, *fakeRoutes) {
	t.Helper()
	routes := &fakeRoutes{}
	return &node{
		file:       &conf.File{ExitNode: choice},
		exitClient: routes,
		binder:     &bypass.Binder{},
	}, routes
}

func withGateway(t *testing.T) {
	t.Helper()
	was := defaultInterface
	defaultInterface = func() (bypass.Interface, error) { return bypass.Interface{Name: "en0", Index: 4}, nil }
	t.Cleanup(func() { defaultInterface = was })
}

// The exit node leaving the network — forgotten, or no longer visible under
// a new policy — used to leave the default route pointed into the tunnel,
// where no peer held it any more: no internet, with the log saying
// "routing normally".
func TestExitNodeLeavingRestoresNormalRouting(t *testing.T) {
	withGateway(t)
	n, routes := exitNode(t, "tenet")

	n.applyUseExit(&netmap.NetMap{Peers: []netmap.Node{exitPeer("tenet", "10.77.0.1", true)}})
	if !routes.active {
		t.Fatal("did not start using the exit node")
	}

	n.applyUseExit(&netmap.NetMap{})
	if routes.active {
		t.Error("still routing through an exit node that has left the network")
	}
	if n.exitProblem == "" {
		t.Error("the doctor was not told why the exit node is not in use")
	}
}

func TestExitApprovalRevokedRestoresNormalRouting(t *testing.T) {
	withGateway(t)
	n, routes := exitNode(t, "tenet")

	n.applyUseExit(&netmap.NetMap{Peers: []netmap.Node{exitPeer("tenet", "10.77.0.1", true)}})
	n.applyUseExit(&netmap.NetMap{Peers: []netmap.Node{exitPeer("tenet", "10.77.0.1", false)}})
	if routes.active {
		t.Error("still routing through an exit node whose approval was withdrawn")
	}
}

// Moving from one exit node to another used to install the default-route
// halves a second time, which the kernel refuses because they exist.
func TestSwitchingExitNodesInstallsNothingTwice(t *testing.T) {
	withGateway(t)
	n, routes := exitNode(t, "tenet")
	peers := []netmap.Node{exitPeer("tenet", "10.77.0.1", true), exitPeer("gw2", "10.77.0.9", true)}

	n.applyUseExit(&netmap.NetMap{Peers: peers})
	n.file.ExitNode = "gw2"
	n.applyUseExit(&netmap.NetMap{Peers: peers})

	if routes.installs != 1 {
		t.Errorf("installed the redirect %d times, want once", routes.installs)
	}
	if routes.exit != netip.MustParseAddr("10.77.0.9") {
		t.Errorf("routing through %s, want gw2", routes.exit)
	}
}

func TestClearingTheExitNodeStops(t *testing.T) {
	withGateway(t)
	n, routes := exitNode(t, "tenet")
	m := &netmap.NetMap{Peers: []netmap.Node{exitPeer("tenet", "10.77.0.1", true)}}

	n.applyUseExit(m)
	n.file.ExitNode = ""
	n.applyUseExit(m)
	if routes.active || routes.stops != 1 {
		t.Errorf("active=%v stops=%d after clearing the exit node", routes.active, routes.stops)
	}
}

// stuckRoutes cannot be taken down: the redirect stays.
type stuckRoutes struct{ fakeRoutes }

func (s *stuckRoutes) Stop() error { return errors.New("route: not permitted") }

// A stop that fails leaves the redirect in place, and the tunnel's sockets
// must stay out of it until a later netmap manages the stop — not be let go
// on the spot, with nothing ever retrying.
func TestAFailedStopIsRetriedAndKeepsTheBinding(t *testing.T) {
	withGateway(t)
	routes := &stuckRoutes{}
	n := &node{file: &conf.File{ExitNode: "tenet"}, exitClient: routes, binder: &bypass.Binder{}}
	m := &netmap.NetMap{Peers: []netmap.Node{exitPeer("tenet", "10.77.0.1", true)}}
	n.applyUseExit(m)
	if err := n.binder.Bind(bypass.Interface{Name: "en0", Index: 4}); err != nil {
		t.Fatal(err)
	}

	n.file.ExitNode = ""
	n.applyUseExit(m)
	if _, bound := n.binder.Bound(); !bound {
		t.Error("the sockets were let go while the redirect is still in place")
	}
	if _, active := routes.Active(); !active {
		t.Error("the stuck redirect was forgotten, so nothing will retry it")
	}
}
