package netcfg

import (
	"net/netip"
	"testing"
)

func TestUsableEndpointFilters(t *testing.T) {
	cases := []struct {
		addr string
		want bool
		why  string
	}{
		{"192.168.1.50", true, "ordinary LAN address"},
		{"10.0.0.4", true, "private range"},
		{"172.16.3.9", true, "private range"},
		{"203.0.113.7", true, "public address"},
		{"127.0.0.1", false, "loopback"},
		{"169.254.1.1", false, "link-local"},
		{"100.64.0.1", false, "our own mesh range"},
		{"100.98.21.63", false, "another VPN's mesh address"},
		{"0.0.0.0", false, "unspecified"},
		{"224.0.0.1", false, "multicast"},
		{"2001:db8::1", false, "IPv6, deferred until disco can rank paths"},
		{"fe80::1", false, "IPv6 link-local"},
	}

	for _, c := range cases {
		addr := netip.MustParseAddr(c.addr)
		if got := usableEndpoint(addr); got != c.want {
			t.Errorf("usableEndpoint(%s) = %v, want %v (%s)", c.addr, got, c.want, c.why)
		}
	}
}

// An unchanged set of interfaces must produce a byte-identical list, or the
// control server sees a change on every poll and wakes the whole mesh.
func TestLocalEndpointsAreStable(t *testing.T) {
	a := LocalEndpoints(51820)
	b := LocalEndpoints(51820)

	if len(a) != len(b) {
		t.Fatalf("two consecutive calls returned %d and %d endpoints", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("endpoint %d differs between calls: %s vs %s", i, a[i], b[i])
		}
	}
	t.Logf("this host advertises %d endpoint(s): %v", len(a), a)
}

func TestLocalEndpointsNeedAPort(t *testing.T) {
	if eps := LocalEndpoints(0); eps != nil {
		t.Errorf("port 0 produced endpoints: %v", eps)
	}
}

// Whatever this machine reports, none of it may be inside the mesh range —
// that would tell peers to reach us through a tunnel.
func TestLocalEndpointsExcludeMeshAddresses(t *testing.T) {
	for _, e := range LocalEndpoints(51820) {
		if CGNATRange.Contains(e.Addr()) {
			t.Errorf("advertised a mesh address: %s", e)
		}
	}
}
