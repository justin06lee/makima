package netcfg

import (
	"fmt"
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

func delRoute(iface string, r netip.Prefix) error {
	return run("ip", "route", "del", r.String(), "dev", iface)
}

func addRouteVia(r netip.Prefix, gateway netip.Addr) error {
	return run("ip", "route", "add", r.String(), "via", gateway.String())
}

func delRouteVia(r netip.Prefix, gateway netip.Addr) error {
	return run("ip", "route", "del", r.String(), "via", gateway.String())
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

// natComment tags the rules makima installs.
//
// Every rule carries it, and teardown deletes by comment rather than by
// position. Deleting an iptables rule by index is how a daemon removes
// somebody else's firewall rule after the table has shifted underneath it.
const natComment = "makima-exit"

// enableForwarding makes this machine route and masquerade for the mesh.
//
// IP forwarding plus a MASQUERADE rule is the whole of it. The masquerade is
// the part people forget: without it the upstream router sees a packet sourced
// from 100.64.0.5, has no route back, and drops the reply — so the tunnel
// looks like it works right up until nothing answers.
func enableForwarding(iface string) error {
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable IP forwarding: %w", err)
	}

	if err := run("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", CGNATRange.String(), "!", "-o", iface,
		"-m", "comment", "--comment", natComment,
		"-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("install NAT rule (is iptables available?): %w", err)
	}

	// Accept both directions explicitly. A default-DROP FORWARD chain is
	// common on anything that has been hardened, and the masquerade rule alone
	// would then be installed on a machine that still refuses to forward.
	if err := run("iptables", "-A", "FORWARD", "-i", iface,
		"-m", "comment", "--comment", natComment, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("allow forwarding from the tunnel: %w", err)
	}
	return run("iptables", "-A", "FORWARD", "-o", iface,
		"-m", "comment", "--comment", natComment, "-j", "ACCEPT")
}

func disableForwarding(iface string) error {
	var firstErr error
	del := func(args ...string) {
		if err := run("iptables", args...); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	del("-t", "nat", "-D", "POSTROUTING",
		"-s", CGNATRange.String(), "!", "-o", iface,
		"-m", "comment", "--comment", natComment, "-j", "MASQUERADE")
	del("-D", "FORWARD", "-i", iface, "-m", "comment", "--comment", natComment, "-j", "ACCEPT")
	del("-D", "FORWARD", "-o", iface, "-m", "comment", "--comment", natComment, "-j", "ACCEPT")

	// ip_forward is deliberately left on. It is a machine-wide setting that
	// something else may depend on, and turning it off because makima happened
	// to turn it on would be a surprising thing for a VPN to do to a router.
	return firstErr
}
