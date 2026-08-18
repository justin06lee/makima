package netcfg

import (
	"net/netip"
)

// setAddr configures the interface via iproute2.
//
// The address is added as a /32 rather than the full CGNAT prefix. Claiming
// the whole /10 as on-link would make the kernel believe every mesh address is
// directly reachable, which is exactly the routing decision we want to make
// explicitly per-peer instead.
func setAddr(iface string, addr netip.Addr) error {
	if err := run("ip", "addr", "add", addr.String()+"/32", "dev", iface); err != nil {
		return err
	}
	return run("ip", "link", "set", "dev", iface, "up")
}

func addRoute(iface string, r netip.Prefix) error {
	return run("ip", "route", "add", r.String(), "dev", iface)
}
