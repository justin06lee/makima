package hostaddr

import (
	"net"
	"net/netip"
	"strings"
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
		{"2001:db8::1", true, "global IPv6: no NAT in the way"},
		{"2600:1702:891b:aa00::39", true, "global IPv6"},
		{"fe80::1", false, "IPv6 link-local"},
		{"fd12:3456::1", false, "a router's unique-local address"},
		{"fd7a:115c:a1e0::1a:2b3c", false, "Tailscale's unique-local range"},
		{"ff02::1", false, "IPv6 multicast"},
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
	for _, name := range []string{
		"docker0", "br-3f2a9c1d7e10", "veth9a1b2c3", "virbr0", "vnet3", "lxdbr0", "cni0", "cali12ab", "podman1", "vmnet8", "vboxnet0",
		"l4tbr0",                 // a Jetson's USB-gadget bridge: 192.168.55.1 on every Jetson
		"bridge100", "bridge101", // macOS vmnet: UTM, Docker Desktop, OrbStack, Lima, Internet Sharing
		"vnic0", "vnic1", // Parallels on macOS
		"mpqemubr0",                 // Multipass on Linux
		"kube-bridge", "kube-ipvs0", // kube-router's pod bridge, kube-proxy's service addresses
		"waydroid0", // Waydroid's container bridge
	} {
		if !hostOnly(name) {
			t.Errorf("%s is treated as a way to reach this machine", name)
		}
	}
	for _, name := range []string{
		"en0", "eth0", "wlan0", "enp2s0", "wlp3s0", "utun4", "makima0",
		"bridge0", "bridge1", // macOS Thunderbolt Bridge and bridges of the owner's own: a cable to another machine
		"usb0", // USB tethering to a phone: the machine's way out
		"wlP1p1s0", "enx00e04c680001",
	} {
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

// IPv4 goes first, and what this machine was observed at before its own
// IPv6 addresses: a peer probes ten candidates at most, and the public IPv4
// address that gets through most NATs must not be crowded out by a handful
// of IPv6 ones.
func TestEndpointsPutIPv4First(t *testing.T) {
	ap := netip.MustParseAddrPort
	local := []netip.AddrPort{ap("192.168.1.213:51820"), ap("[2600:1702:891b:aa00::39]:51820"), ap("[2600:1702:891b:aa00:16d:4d00:2c8f:b723]:51820")}
	got := Endpoints(local, ap("107.214.144.123:6505"), ap("[2600:1702:891b:aa00:7ad3:ffe1:1b5b:ee6f]:51820"), ap("192.168.1.213:51820"))
	want := []netip.AddrPort{
		ap("192.168.1.213:51820"),
		ap("107.214.144.123:6505"),
		ap("[2600:1702:891b:aa00::39]:51820"),
		ap("[2600:1702:891b:aa00:16d:4d00:2c8f:b723]:51820"),
		ap("[2600:1702:891b:aa00:7ad3:ffe1:1b5b:ee6f]:51820"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// An address the OS no longer offers for new traffic — a temporary address
// past its preferred lifetime, one still being checked for duplicates, or a
// duplicate — is not one to send peers to.
func TestIfInet6Flags(t *testing.T) {
	const table = `not an address line at all
26001702891baa00016d4d002c8fb723 03 40 00 00 wlP1p1s0
26001702891baa007ad3ffe11b5bee6f 03 40 00 01 wlP1p1s0
26001702891baa00aaaabbbbccccdddd 03 40 00 21 wlP1p1s0
26001702891baa000000000000000042 03 40 00 40 wlP1p1s0
fe80000000000000521e91fffe9599f5 03 40 20 80 wlP1p1s0
`
	flags := parseIfInet6(strings.NewReader(table))
	for addr, want := range map[string]bool{
		"2600:1702:891b:aa00:16d:4d00:2c8f:b723":  false, // stable
		"2600:1702:891b:aa00:7ad3:ffe1:1b5b:ee6f": false, // temporary, preferred: what outbound traffic leaves from
		"2600:1702:891b:aa00:aaaa:bbbb:cccc:dddd": true,  // temporary, deprecated
		"2600:1702:891b:aa00::42":                 true,  // tentative
	} {
		f, ok := flags[netip.MustParseAddr(addr)]
		if !ok {
			t.Errorf("%s not parsed", addr)
			continue
		}
		if got := f&linuxV6Unusable != 0; got != want {
			t.Errorf("%s (flags %#x) unusable = %v, want %v", addr, f, got, want)
		}
	}
	if len(flags) != 5 {
		t.Errorf("parsed %d addresses, want the 5 well-formed ones: %v", len(flags), flags)
	}
}
