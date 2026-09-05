package main

import (
	"net/netip"
	"reflect"
	"testing"
)

// Tailscale and makima both hand out 100.64.0.0/10, and a machine running
// both has a tunnel that looks fine and passes nothing. The doctor has to
// name the other interface, and must not name makima's own.
func TestOtherCGNATInterfaces(t *testing.T) {
	p := netip.MustParsePrefix
	ifaces := []ifaceAddrs{
		{name: "lo0", addrs: []netip.Prefix{p("127.0.0.1/8")}},
		{name: "en0", addrs: []netip.Prefix{p("192.168.1.20/24")}},
		{name: "utun4", addrs: []netip.Prefix{p("fe80::1/64"), p("100.98.21.63/32")}},
		{name: "utun7", addrs: []netip.Prefix{p("100.64.0.3/32")}},
		{name: "tailscale0", addrs: []netip.Prefix{p("100.102.72.87/32")}},
	}

	got := otherCGNATInterfaces(ifaces, "utun7")
	want := []string{"utun4", "tailscale0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("otherCGNATInterfaces = %v, want %v", got, want)
	}

	if got := otherCGNATInterfaces(ifaces[:2], "utun7"); got != nil {
		t.Errorf("a machine with no other VPN was flagged: %v", got)
	}
}

// The real interface list is readable, whatever is on it.
func TestListInterfacesDoesNotPanic(t *testing.T) {
	for _, i := range listInterfaces() {
		if i.name == "" {
			t.Error("an interface with no name")
		}
	}
}
