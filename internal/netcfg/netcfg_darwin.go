package netcfg

import (
	"net/netip"
)

// setAddr configures a utun interface on macOS.
//
// utun devices are point-to-point, so ifconfig wants both a local and a
// destination address. We pass the same address for both with a /32 mask:
// there is no single peer on the other end of a mesh, and the routes added
// afterwards are what actually steer traffic.
func setAddr(iface string, addr netip.Addr) error {
	a := addr.String()
	return run("ifconfig", iface, "inet", a, a, "netmask", "255.255.255.255", "up")
}

func addRoute(iface string, r netip.Prefix) error {
	// -q suppresses the noise, -n skips reverse DNS on the output. Adding a
	// route that already exists is an error on macOS, so this is not
	// idempotent by itself; callers configure a freshly created interface.
	return run("route", "-q", "-n", "add", "-inet", r.String(), "-interface", iface)
}
