package control

import (
	"net/netip"
	"testing"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/policy"
)

// joinNamed registers a node and returns the machine key it speaks as.
func joinNamed(t *testing.T, s *Store, name string) (key.Private, *Node) {
	t.Helper()

	auth, err := s.MintAuthKey(true, 0)
	if err != nil {
		t.Fatal(err)
	}
	machineKey, _ := key.NewPrivate()
	nodeKey, _ := key.NewPrivate()
	discoKey, _ := key.NewPrivate()

	n, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: name, NodeKey: nodeKey.Public(), DiscoKey: discoKey.Public(), AuthKey: auth.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	return machineKey, n
}

// --- relays -------------------------------------------------------------

// Every node must be assigned the same relay: two nodes can only meet on one
// they are both connected to.
func TestEveryNodeGetsTheSameRelay(t *testing.T) {
	s := newStore(t)

	relayKey, _ := key.NewPrivate()
	if err := s.AddRelay("relay.example:3478", relayKey.Public()); err != nil {
		t.Fatal(err)
	}

	a, _ := joinNamed(t, s, "laptop")
	b, _ := joinNamed(t, s, "desktop")

	for _, mk := range []key.Private{a, b} {
		resp, err := s.NetMapFor(mk.Public())
		if err != nil {
			t.Fatal(err)
		}
		if resp.HomeRelay.URL != "relay.example:3478" {
			t.Errorf("home relay is %q, want relay.example:3478", resp.HomeRelay.URL)
		}
		if resp.HomeRelay.Key != relayKey.Public() {
			t.Error("the relay's pinned key did not reach the netmap")
		}
		for _, p := range resp.Peers {
			if p.RelayURL != "relay.example:3478" {
				t.Errorf("peer %s is advertised on relay %q", p.Name, p.RelayURL)
			}
		}
	}
}

func TestPreferRelayMovesTheMesh(t *testing.T) {
	s := newStore(t)

	if err := s.AddRelay("first:3478", key.Public{}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRelay("second:3478", key.Public{}); err != nil {
		t.Fatal(err)
	}

	mk, _ := joinNamed(t, s, "laptop")

	resp, _ := s.NetMapFor(mk.Public())
	if resp.HomeRelay.URL != "first:3478" {
		t.Fatalf("initial relay is %q, want first:3478", resp.HomeRelay.URL)
	}

	if err := s.PreferRelay("second:3478"); err != nil {
		t.Fatal(err)
	}

	resp, _ = s.NetMapFor(mk.Public())
	if resp.HomeRelay.URL != "second:3478" {
		t.Errorf("after prefer, relay is %q, want second:3478", resp.HomeRelay.URL)
	}
}

func TestRelayChangeBumpsTheVersion(t *testing.T) {
	s := newStore(t)
	joinNamed(t, s, "laptop")

	before := s.Version()
	if err := s.AddRelay("relay:3478", key.Public{}); err != nil {
		t.Fatal(err)
	}
	if s.Version() <= before {
		t.Error("adding a relay did not bump the netmap version; nodes would not be told")
	}
}

func TestDuplicateRelayRefused(t *testing.T) {
	s := newStore(t)
	if err := s.AddRelay("relay:3478", key.Public{}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRelay("relay:3478", key.Public{}); err == nil {
		t.Error("the same relay was registered twice")
	}
}

// --- routes -------------------------------------------------------------

// A node can claim any prefix it likes, including one that would hijack the
// whole internet. Nothing is published until an operator approves it.
func TestAdvertisedRoutesAreNotPublishedUntilApproved(t *testing.T) {
	s := newStore(t)

	auth, _ := s.MintAuthKey(true, 0)
	routerMachine, _ := key.NewPrivate()
	routerNode, _ := key.NewPrivate()
	subnet := netip.MustParsePrefix("192.168.1.0/24")

	if _, err := s.Register(routerMachine.Public(), &RegisterRequest{
		Name: "router", NodeKey: routerNode.Public(), AuthKey: auth.Secret,
		AdvertiseRoutes: []netip.Prefix{subnet},
	}); err != nil {
		t.Fatal(err)
	}

	viewer, _ := joinNamed(t, s, "laptop")

	resp, err := s.NetMapFor(viewer.Public())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Peers) != 1 {
		t.Fatalf("%d peers, want 1", len(resp.Peers))
	}
	if len(resp.Peers[0].AllowedIPs) != 0 {
		t.Errorf("an unapproved route reached the netmap: %v", resp.Peers[0].AllowedIPs)
	}

	if err := s.ApproveRoutes("router", []netip.Prefix{subnet}, false); err != nil {
		t.Fatal(err)
	}

	resp, _ = s.NetMapFor(viewer.Public())
	if len(resp.Peers[0].AllowedIPs) != 1 || resp.Peers[0].AllowedIPs[0] != subnet {
		t.Errorf("after approval the routes are %v, want [%s]", resp.Peers[0].AllowedIPs, subnet)
	}
}

// Approving something a node never offered would let an operator route traffic
// into a machine that has no idea it is expected to forward it.
func TestCannotApproveAnUnadvertisedRoute(t *testing.T) {
	s := newStore(t)
	joinNamed(t, s, "laptop")

	if err := s.ApproveRoutes("laptop", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false); err == nil {
		t.Error("a route the node never advertised was approved")
	}
}

// An approval must not survive the node withdrawing its offer and later
// re-making it — that would be approval granted once, applied forever.
func TestApprovalDoesNotSurviveWithdrawal(t *testing.T) {
	s := newStore(t)

	auth, _ := s.MintAuthKey(true, 0)
	machineKey, _ := key.NewPrivate()
	nodeKey, _ := key.NewPrivate()
	subnet := netip.MustParsePrefix("192.168.1.0/24")

	req := &RegisterRequest{
		Name: "router", NodeKey: nodeKey.Public(), AuthKey: auth.Secret,
		AdvertiseRoutes: []netip.Prefix{subnet},
	}
	if _, err := s.Register(machineKey.Public(), req); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveRoutes("router", []netip.Prefix{subnet}, false); err != nil {
		t.Fatal(err)
	}

	// The node stops advertising.
	if _, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: "router", NodeKey: nodeKey.Public(),
	}); err != nil {
		t.Fatal(err)
	}

	// And starts again.
	after, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: "router", NodeKey: nodeKey.Public(), AdvertiseRoutes: []netip.Prefix{subnet},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(after.ApprovedRoutes) != 0 {
		t.Errorf("a stale approval was reactivated: %v", after.ApprovedRoutes)
	}
}

// An exit node is published as two halves rather than 0.0.0.0/0, so it loses
// to any more specific route by longest-prefix match.
func TestExitNodePublishesDefaultHalves(t *testing.T) {
	s := newStore(t)

	auth, _ := s.MintAuthKey(true, 0)
	exitMachine, _ := key.NewPrivate()
	exitNode, _ := key.NewPrivate()

	if _, err := s.Register(exitMachine.Public(), &RegisterRequest{
		Name: "gateway", NodeKey: exitNode.Public(), AuthKey: auth.Secret, AdvertiseExit: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveRoutes("gateway", nil, true); err != nil {
		t.Fatal(err)
	}

	viewer, _ := joinNamed(t, s, "laptop")
	resp, _ := s.NetMapFor(viewer.Public())

	got := map[string]bool{}
	for _, r := range resp.Peers[0].AllowedIPs {
		got[r.String()] = true
	}
	if !got["0.0.0.0/1"] || !got["128.0.0.0/1"] {
		t.Errorf("exit node publishes %v, want the two default halves", resp.Peers[0].AllowedIPs)
	}
	if got["0.0.0.0/0"] {
		t.Error("exit node published a real default route, which would outrank nothing")
	}
}

// --- policy -------------------------------------------------------------

// A peer the policy forbids is not merely blocked, it is never named.
func TestPolicyTrimsTheNetmap(t *testing.T) {
	s := newStore(t)

	viewer, _ := joinNamed(t, s, "laptop")
	joinNamed(t, s, "server")
	joinNamed(t, s, "printer")

	if err := s.SetPolicy(&policy.Policy{ACLs: []policy.Rule{
		{Action: "accept", Src: []string{"laptop"}, Dst: []string{"server:*"}},
	}}); err != nil {
		t.Fatal(err)
	}

	resp, err := s.NetMapFor(viewer.Public())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Peers) != 1 || resp.Peers[0].Name != "server" {
		var names []string
		for _, p := range resp.Peers {
			names = append(names, p.Name)
		}
		t.Errorf("laptop sees %v, want just [server]", names)
	}
}

// The compiled filter has to reach the node, because ports cannot be expressed
// by trimming the peer list.
func TestNetmapCarriesTheFilter(t *testing.T) {
	s := newStore(t)

	_, serverNode := joinNamed(t, s, "server")
	serverMachine := serverNode.MachineKey
	joinNamed(t, s, "laptop")

	if err := s.SetPolicy(&policy.Policy{ACLs: []policy.Rule{
		{Action: "accept", Src: []string{"laptop"}, Dst: []string{"server:22"}},
	}}); err != nil {
		t.Fatal(err)
	}

	resp, err := s.NetMapFor(serverMachine)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Filter == nil || len(resp.Filter.Matches) == 0 {
		t.Fatal("the server's netmap carries no packet filter")
	}

	laptopAddr := netip.MustParseAddr("100.64.0.2")
	serverAddr := resp.Self.Addresses[0].Addr()

	if !resp.Filter.Allow(laptopAddr, serverAddr, 22) {
		t.Error("the filter blocks the ssh the policy permits")
	}
	if resp.Filter.Allow(laptopAddr, serverAddr, 80) {
		t.Error("the filter permits http the policy does not")
	}
}

func TestInvalidPolicyRefused(t *testing.T) {
	s := newStore(t)
	if err := s.SetPolicy(&policy.Policy{ACLs: []policy.Rule{
		{Action: "deny", Src: []string{"*"}, Dst: []string{"*:*"}},
	}}); err == nil {
		t.Error("a policy with a deny rule was stored")
	}
}

// Tags come from the credential, never from the node: a node that could tag
// itself could grant itself whatever access the tag confers.
func TestTagsComeFromTheAuthKey(t *testing.T) {
	s := newStore(t)

	auth, err := s.MintAuthKeyTagged(true, 0, []string{"server"})
	if err != nil {
		t.Fatal(err)
	}
	machineKey, _ := key.NewPrivate()
	nodeKey, _ := key.NewPrivate()

	n, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: "db", NodeKey: nodeKey.Public(), AuthKey: auth.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Tags) != 1 || n.Tags[0] != "server" {
		t.Errorf("tags are %v, want [server]", n.Tags)
	}
}

func TestTaggedPolicyMatching(t *testing.T) {
	s := newStore(t)

	auth, _ := s.MintAuthKeyTagged(true, 0, []string{"server"})
	serverMachine, _ := key.NewPrivate()
	serverNode, _ := key.NewPrivate()
	if _, err := s.Register(serverMachine.Public(), &RegisterRequest{
		Name: "db", NodeKey: serverNode.Public(), AuthKey: auth.Secret,
	}); err != nil {
		t.Fatal(err)
	}

	viewer, _ := joinNamed(t, s, "laptop")
	joinNamed(t, s, "printer")

	if err := s.SetPolicy(&policy.Policy{ACLs: []policy.Rule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{"tag:server:*"}},
	}}); err != nil {
		t.Fatal(err)
	}

	resp, _ := s.NetMapFor(viewer.Public())
	if len(resp.Peers) != 1 || resp.Peers[0].Name != "db" {
		var names []string
		for _, p := range resp.Peers {
			names = append(names, p.Name)
		}
		t.Errorf("laptop sees %v, want just the tagged [db]", names)
	}
}

// --- expiry --------------------------------------------------------------

// Expiring is not forgetting: the node keeps its address but has to prove
// itself again.
func TestExpiredNodeMustReauthenticate(t *testing.T) {
	s := newStore(t)

	auth, _ := s.MintAuthKey(true, 0)
	machineKey, _ := key.NewPrivate()
	nodeKey, _ := key.NewPrivate()

	before, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: "laptop", NodeKey: nodeKey.Public(), AuthKey: auth.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := before.Address

	if err := s.ExpireNode("laptop"); err != nil {
		t.Fatal(err)
	}

	// Reconnecting on the machine key alone must not work, or "expire the
	// stolen laptop" would be undone by the laptop simply reconnecting.
	if _, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: "laptop", NodeKey: nodeKey.Public(),
	}); err == nil {
		t.Fatal("an expired node re-registered without a credential")
	}

	fresh, _ := s.MintAuthKey(false, 0)
	after, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: "laptop", NodeKey: nodeKey.Public(), AuthKey: fresh.Secret,
	})
	if err != nil {
		t.Fatalf("a fresh credential did not readmit the node: %v", err)
	}
	if after.Address != addr {
		t.Errorf("the node's address changed from %s to %s; expiry is not forgetting", addr, after.Address)
	}
}

// --- dns ------------------------------------------------------------------

func TestDNSSettingsReachTheNetmap(t *testing.T) {
	s := newStore(t)
	mk, _ := joinNamed(t, s, "laptop")

	resp, _ := s.NetMapFor(mk.Public())
	if resp.DNS.Enabled {
		t.Error("mesh DNS is on by default")
	}

	if err := s.SetDNS(true, "home"); err != nil {
		t.Fatal(err)
	}

	resp, _ = s.NetMapFor(mk.Public())
	if !resp.DNS.Enabled || resp.Domain != "home" {
		t.Errorf("netmap DNS is %+v with domain %q, want enabled under \"home\"", resp.DNS, resp.Domain)
	}
}

func TestDefaultDomainIsUsedWhenUnset(t *testing.T) {
	s := newStore(t)
	mk, _ := joinNamed(t, s, "laptop")

	resp, _ := s.NetMapFor(mk.Public())
	if resp.Domain != DefaultDomain {
		t.Errorf("domain is %q, want the default %q", resp.Domain, DefaultDomain)
	}
}

// The disco key has to reach peers, or they cannot seal a probe to it and
// every path stays relayed.
func TestDiscoKeyReachesPeers(t *testing.T) {
	s := newStore(t)

	viewer, _ := joinNamed(t, s, "laptop")
	_, peer := joinNamed(t, s, "desktop")

	resp, _ := s.NetMapFor(viewer.Public())
	if len(resp.Peers) != 1 {
		t.Fatalf("%d peers, want 1", len(resp.Peers))
	}
	if resp.Peers[0].DiscoKey != peer.DiscoKey {
		t.Error("the peer's disco key did not reach the netmap; probing would be impossible")
	}
}
