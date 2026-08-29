package netcfg

import (
	"fmt"
	"net/netip"
	"os/exec"
)

// Linux has two answers and this tries the better one first.
//
// systemd-resolved supports genuine split DNS: a per-interface nameserver with
// a routing domain, so mesh names go to the mesh resolver and nothing else
// changes. Where it is running, `resolvectl` is the whole implementation.
//
// Where it is not, there is no per-interface mechanism at all — /etc/resolv.conf
// is a single global list with no notion of which name goes where. Rewriting
// it would make the mesh resolver authoritative for *every* lookup on the
// machine, which is exactly the takeover this package exists to avoid. So the
// fallback is to do nothing and say so: mesh names will not resolve, and the
// operator gets an error explaining why rather than a machine whose DNS
// quietly now belongs to a tunnel.

func setResolver(iface, domain string, server netip.Addr) error {
	if !haveResolvectl() {
		return fmt.Errorf(
			"mesh DNS needs systemd-resolved for split DNS, and resolvectl was not found.\n"+
				"Without it, pointing the system at the mesh resolver would capture every lookup on this machine, not just *.%s.\n"+
				"Peers are still reachable by address; disable mesh DNS with 'makima-server dns off' to stop this warning.",
			domain)
	}

	if err := run("resolvectl", "dns", iface, server.String()); err != nil {
		return err
	}
	// The leading tilde is what makes this a *routing* domain rather than a
	// search domain: queries for it are routed here, and queries for anything
	// else are not.
	if err := run("resolvectl", "domain", iface, "~"+domain); err != nil {
		return err
	}
	// This interface is not a general resolver, and saying so stops resolved
	// from sending it unrelated queries when other links are unavailable.
	return run("resolvectl", "default-route", iface, "false")
}

func clearResolver(iface, domain string) error {
	if !haveResolvectl() {
		return nil
	}
	// Reverting the interface drops the nameserver and the domain together,
	// which is both simpler and less likely to leave half a configuration
	// behind than unsetting them one at a time.
	return run("resolvectl", "revert", iface)
}

func haveResolvectl() bool {
	_, err := exec.LookPath("resolvectl")
	return err == nil
}
