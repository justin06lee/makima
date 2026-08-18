// Package netcfg assigns addresses and routes to the TUN interface.
//
// wireguard-go hands you a working tunnel and nothing else — it never touches
// the host's network configuration. Somebody has to tell the OS "this
// interface owns 100.64.0.3, and the 100.64.0.0/10 range goes down it", and
// that somebody is unavoidably per-platform. This package is that seam.
package netcfg

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// CGNATRange is the address space makima hands out, matching Tailscale's
// choice of 100.64.0.0/10. It is RFC 6598 carrier-grade NAT space: routable
// enough to be useful, reserved enough that it almost never collides with a
// home or office LAN the way 10/8 and 192.168/16 constantly do.
var CGNATRange = netip.MustParsePrefix("100.64.0.0/10")

// Configure gives iface the address addr and points routes down it.
func Configure(iface string, addr netip.Addr, routes []netip.Prefix) error {
	if err := setAddr(iface, addr); err != nil {
		return fmt.Errorf("assign %s to %s: %w", addr, iface, err)
	}
	for _, r := range routes {
		if err := addRoute(iface, r); err != nil {
			return fmt.Errorf("route %s via %s: %w", r, iface, err)
		}
	}
	return nil
}

// run executes a network configuration command, folding stderr into the error
// so a failure says what the OS actually complained about.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}
