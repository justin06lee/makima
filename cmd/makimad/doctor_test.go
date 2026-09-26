package main

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/justin06lee/makima/internal/hostaddr"
)

// A network started by an older makima is in 100.64.0.0/10, Tailscale's
// range, and a machine running both has a tunnel that looks fine and passes
// nothing. The doctor has to name the other interface, and must not name
// makima's own.
func TestOtherInterfacesInLegacyRange(t *testing.T) {
	p := netip.MustParsePrefix
	ifaces := []ifaceAddrs{
		{name: "lo0", addrs: []netip.Prefix{p("127.0.0.1/8")}},
		{name: "en0", addrs: []netip.Prefix{p("192.168.1.20/24")}},
		{name: "utun4", addrs: []netip.Prefix{p("fe80::1/64"), p("100.98.21.63/32")}},
		{name: "utun7", addrs: []netip.Prefix{p("100.64.0.3/32")}},
		{name: "tailscale0", addrs: []netip.Prefix{p("100.102.72.87/32")}},
	}

	got := otherInterfacesIn(ifaces, "utun7", hostaddr.LegacyMeshRange)
	want := []string{"utun4", "tailscale0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("otherInterfacesIn = %v, want %v", got, want)
	}

	if got := otherInterfacesIn(ifaces[:2], "utun7", hostaddr.LegacyMeshRange); got != nil {
		t.Errorf("a machine with no other VPN was flagged: %v", got)
	}
}

// On makima's own range, Tailscale running beside it is not a conflict.
func TestTailscaleIsNoConflictOnMakimasOwnRange(t *testing.T) {
	p := netip.MustParsePrefix
	ifaces := []ifaceAddrs{
		{name: "utun7", addrs: []netip.Prefix{p("10.77.0.3/32")}},
		{name: "tailscale0", addrs: []netip.Prefix{p("100.102.72.87/32")}},
	}
	if got := otherInterfacesIn(ifaces, "utun7", hostaddr.MeshRange); got != nil {
		t.Errorf("Tailscale was flagged against makima's own range: %v", got)
	}
}
