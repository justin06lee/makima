package hostaddr

import (
	"net"
	"net/netip"
	"testing"
)

// The kernel answers for every IPv6 address this Mac has, and refuses one it
// does not have rather than calling it usable.
func TestDarwinV6Flags(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	asked := 0
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, _ := netip.AddrFromSlice(ipnet.IP)
			if !addr.Is6() || addr.Is4In6() || !addr.IsGlobalUnicast() {
				continue
			}
			f, err := darwinV6Flags(ifc.Name, addr)
			if err != nil {
				t.Errorf("%s on %s: %v", addr, ifc.Name, err)
				continue
			}
			asked++
			t.Logf("%s on %s: flags %#x, unusable %v", addr, ifc.Name, f, f&darwinV6Unusable != 0)
		}
	}
	if asked == 0 {
		t.Log("no global IPv6 address here to ask about")
	}
	if _, err := darwinV6Flags("lo0", netip.MustParseAddr("2001:db8::dead")); err == nil {
		t.Error("an address this machine does not have was answered for")
	}
}
