package netcfg

import (
	"fmt"
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
	// -q suppresses the banner, -n skips reverse DNS on the output.
	return run("route", "-q", "-n", "add", "-inet", r.String(), "-interface", iface)
}

func delRoute(iface string, r netip.Prefix) error {
	return run("route", "-q", "-n", "delete", "-inet", r.String(), "-interface", iface)
}

func addRouteVia(r netip.Prefix, gateway netip.Addr) error {
	return run("route", "-q", "-n", "add", "-inet", r.String(), gateway.String())
}

func delRouteVia(r netip.Prefix, gateway netip.Addr) error {
	return run("route", "-q", "-n", "delete", "-inet", r.String(), gateway.String())
}

func addDefaultViaInterface(iface string) error {
	for _, h := range defaultHalves {
		if err := addRoute(iface, h); err != nil {
			return err
		}
	}
	return nil
}

func delDefaultViaInterface(iface string) error {
	var firstErr error
	for _, h := range defaultHalves {
		// Every half is attempted even after a failure: leaving one installed
		// would silently keep half the internet inside the tunnel.
		if err := delRoute(iface, h); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// enableForwarding turns this machine into a router for the mesh.
//
// pfctl is macOS's only NAT mechanism, and configuring it from a daemon means
// either owning /etc/pf.conf — which would clobber anything else using it — or
// loading an anchor. Neither is safe to do behind an operator's back on a
// desktop machine, so exit nodes and subnet routers are supported on Linux and
// refused here, with an error that says so rather than a half-working setup.
func enableForwarding(iface string) error {
	return fmt.Errorf(
		"advertising routes or acting as an exit node needs NAT, which on macOS means editing the system pf configuration.\n" +
			"makima will not do that to a machine behind your back. Run subnet routers and exit nodes on Linux, " +
			"or configure pf yourself and the tunnel side will work.")
}

func disableForwarding(iface string) error { return nil }
