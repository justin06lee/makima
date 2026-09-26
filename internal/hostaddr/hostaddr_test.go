package hostaddr

import (
	"net"
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
		if IsMeshAddr(e.Addr()) {
			t.Errorf("advertised a mesh address: %s", e)
		}
	}
}

// Container and VM bridges lead only into this host, carry the same address
// on every host that runs the same software, and appear whenever a container
// starts. None of that is a path to this machine, or a change of network.
func TestHostOnlyBridgesAreNotPaths(t *testing.T) {
	for _, name := range []string{"docker0", "br-3f2a9c1d7e10", "veth9a1b2c3", "virbr0", "vnet3", "lxdbr0", "cni0", "cali12ab", "podman1", "vmnet8", "vboxnet0"} {
		if !hostOnly(name) {
			t.Errorf("%s is treated as a way to reach this machine", name)
		}
	}
	for _, name := range []string{"en0", "eth0", "wlan0", "enp2s0", "wlp3s0", "bridge0", "utun4", "makima0"} {
		if hostOnly(name) {
			t.Errorf("%s is treated as a host-only bridge", name)
		}
	}
}

// Tailscale starting or stopping is not this machine changing networks. Its
// IPv6 address is unique-local, which Go counts as global unicast, so it used
// to enter the fingerprint and every toggle dropped every path makima had.
func TestAVPNsAddressesDoNotSayWhereWeAre(t *testing.T) {
	lan := net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	tunnel := net.FlagUp | net.FlagPointToPoint | net.FlagMulticast

	for _, c := range []struct {
		addr  string
		flags net.Flags
		want  bool
	}{
		{"192.168.1.20", lan, true},
		{"2001:db8:1:2::20", lan, true},
		{"fd7a:115c:a1e0::1a:2b3c", tunnel, false}, // Tailscale
		{"fd12:3456::1", lan, false},               // a router's ULA
		{"100.101.102.103", tunnel, false},         // Tailscale, IPv4
		{"10.8.0.6", tunnel, false},                // OpenVPN, WireGuard
		{"203.0.113.9", tunnel, true},              // PPPoE: the real connection
	} {
		if got := saysWhereWeAre(netip.MustParseAddr(c.addr), c.flags); got != c.want {
			t.Errorf("%s on %v: %v, want %v", c.addr, c.flags, got, c.want)
		}
	}
}
