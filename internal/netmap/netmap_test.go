package netmap

import (
	"net/netip"
	"testing"

	"github.com/justin06lee/makima/internal/key"
)

func testMap(t *testing.T) *NetMap {
	t.Helper()
	priv, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	return &NetMap{
		PrivateKey: priv,
		ListenPort: 51820,
		Self: Node{
			ID: 1, Name: "laptop", Key: priv.Public(),
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		Peers: []Node{{
			ID: 2, Name: "gateway", Key: peerKey.Public(),
			Addresses:  []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")},
			Endpoints:  []netip.AddrPort{netip.MustParseAddrPort("198.51.100.4:51820")},
		}},
	}
}

// A subnet router's AllowedIPs is the union of what it owns and what it
// routes. Dropping either half breaks a different thing: lose the addresses
// and the peer itself is unreachable, lose the routes and the subnet behind
// it is.
func TestWireGuardConfigUnionsAllowedIPs(t *testing.T) {
	cfg := testMap(t).WireGuardConfig()

	if len(cfg.Peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(cfg.Peers))
	}
	got := cfg.Peers[0].AllowedIPs
	want := []string{"100.64.0.2/32", "192.168.7.0/24"}
	if len(got) != len(want) {
		t.Fatalf("got AllowedIPs %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("AllowedIPs[%d] = %s, want %s", i, got[i], w)
		}
	}
}

func TestWireGuardConfigCarriesEndpoint(t *testing.T) {
	cfg := testMap(t).WireGuardConfig()
	ep := cfg.Peers[0].Endpoint
	if ep == nil {
		t.Fatal("endpoint was dropped")
	}
	if ep.String() != "198.51.100.4:51820" {
		t.Errorf("endpoint = %s, want 198.51.100.4:51820", ep)
	}
}

// Taking the address of a range variable is a classic way to give every peer
// the last peer's endpoint. Guard against it explicitly.
func TestEndpointsAreNotAliased(t *testing.T) {
	m := testMap(t)
	k2, _ := key.NewPrivate()
	m.Peers = append(m.Peers, Node{
		ID: 3, Name: "phone", Key: k2.Public(),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:41641")},
	})

	cfg := m.WireGuardConfig()
	a, b := cfg.Peers[0].Endpoint, cfg.Peers[1].Endpoint
	if a == b {
		t.Fatal("two peers share one endpoint pointer")
	}
	if a.String() == b.String() {
		t.Fatalf("both peers got endpoint %s", a)
	}
}

func TestRoutesCoverPeersAndSubnets(t *testing.T) {
	routes := testMap(t).Routes()
	want := map[string]bool{"100.64.0.2/32": false, "192.168.7.0/24": false}
	for _, r := range routes {
		if _, ok := want[r.String()]; ok {
			want[r.String()] = true
		}
	}
	for prefix, seen := range want {
		if !seen {
			t.Errorf("route %s missing from %v", prefix, routes)
		}
	}
}

// Routes must never include the node's own address: installing a route for
// yourself pointing down the tunnel is a loop.
func TestRoutesExcludeSelf(t *testing.T) {
	m := testMap(t)
	selfAddr, err := m.Self.Addr()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.Routes() {
		if r.Addr() == selfAddr {
			t.Errorf("routes contain this node's own address %s", selfAddr)
		}
	}
}

func TestAddrErrorsWhenUnset(t *testing.T) {
	var n Node
	if _, err := n.Addr(); err == nil {
		t.Error("Addr() on an address-less node should fail")
	}
}
