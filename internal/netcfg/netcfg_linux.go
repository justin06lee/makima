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
// from 10.77.0.5, has no route back, and drops the reply — so the tunnel
// looks like it works right up until nothing answers.
//
// Only the range this network uses. Masquerading 100.64.0.0/10 on a network
// that lives in 10.77.0.0/16 would rewrite Tailscale's traffic on a machine
// running both.
func enableForwarding(iface string, mesh netip.Prefix) error {
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable IP forwarding: %w", err)
	}

	// Whatever an earlier makima left first: v0.3.0 appended its accepts
	// after any DROP, masqueraded Tailscale's range as well, and never took
	// any of it down. Checking for a rule before adding it would find those
	// and leave them as they were.
	_ = removeForwarding(iface, MeshRange, LegacyMeshRange)

	if err := ensureRule("nat", "POSTROUTING", false,
		"-s", mesh.String(), "!", "-o", iface,
		"-m", "comment", "--comment", natComment, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("install NAT rule (is iptables available?): %w", err)
	}

	// Accept both directions explicitly, and first. A default-DROP FORWARD
	// chain is common on anything that has been hardened, and so is a DROP
	// rule at its end; appended after one, these would never be reached.
	if err := ensureRule("filter", "FORWARD", true, "-i", iface,
		"-m", "comment", "--comment", natComment, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("allow forwarding from the tunnel: %w", err)
	}
	return ensureRule("filter", "FORWARD", true, "-o", iface,
		"-m", "comment", "--comment", natComment, "-j", "ACCEPT")
}

// ensureRule adds an iptables rule unless it is already there — a daemon
// killed before it could clean up leaves its rules behind, and adding them
// again on every start would stack them up. first inserts at the top of the
// chain rather than appending.
func ensureRule(table, chain string, first bool, rule ...string) error {
	check := append([]string{"-t", table, "-C", chain}, rule...)
	if run("iptables", check...) == nil {
		return nil
	}
	op := "-A"
	if first {
		op = "-I"
	}
	return run("iptables", append([]string{"-t", table, op, chain}, rule...)...)
}

func disableForwarding(iface string, mesh netip.Prefix) error {
	return removeForwarding(iface, mesh)
}

// removeForwarding deletes every copy of makima's forwarding rules for the
// given mesh ranges.
func removeForwarding(iface string, meshes ...netip.Prefix) error {
	var firstErr error
	// Every copy, in case an earlier makima stacked several: -D removes one
	// at a time, and succeeds until none is left.
	del := func(table, chain string, rule ...string) {
		args := append([]string{"-t", table, "-D", chain}, rule...)
		for i := 0; i < 16; i++ {
			if err := run("iptables", args...); err != nil {
				if i == 0 && firstErr == nil {
					firstErr = err
				}
				return
			}
		}
	}

	for _, mesh := range meshes {
		del("nat", "POSTROUTING", "-s", mesh.String(), "!", "-o", iface,
			"-m", "comment", "--comment", natComment, "-j", "MASQUERADE")
	}
	del("filter", "FORWARD", "-i", iface, "-m", "comment", "--comment", natComment, "-j", "ACCEPT")
	del("filter", "FORWARD", "-o", iface, "-m", "comment", "--comment", natComment, "-j", "ACCEPT")

	// ip_forward is deliberately left on. It is a machine-wide setting that
	// something else may depend on, and turning it off because makima happened
	// to turn it on would be a surprising thing for a VPN to do to a router.
	return firstErr
}
