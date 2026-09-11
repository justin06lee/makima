package netcfg

import (
	"fmt"
	"strconv"
	"strings"
)

// Linux is where this matters, because Linux is where a host firewall is
// likely to be running and silently dropping tunnel traffic.
//
// Four backends, in the order they are checked. The order is deliberate:
// firewalld and ufw both sit on top of nftables or iptables, so finding the
// manager first means configuring it the way it expects rather than writing
// rules underneath it that it will overwrite on its next reload.

func firewallStatus(iface string) Report {
	switch {
	case firewalldRunning():
		trusted := runOK("firewall-cmd", "--permanent", "--zone=trusted", "--query-interface="+iface)
		r := Report{
			Backend:   BackendFirewalld,
			Active:    true,
			Trusted:   trusted,
			Automatic: true,
			Manual: fmt.Sprintf(
				"sudo firewall-cmd --permanent --zone=trusted --add-interface=%s && sudo firewall-cmd --reload", iface),
		}
		if trusted {
			r.Detail = fmt.Sprintf("firewalld is running and %s is in the trusted zone", iface)
		} else {
			r.Detail = fmt.Sprintf("firewalld is running and %s is not trusted, so mesh traffic is being dropped", iface)
		}
		return r

	case ufwActive():
		trusted := ufwAllows(iface)
		r := Report{
			Backend:   BackendUFW,
			Active:    true,
			Trusted:   trusted,
			Automatic: true,
			Manual:    fmt.Sprintf("sudo ufw allow in on %s && sudo ufw route allow in on %s", iface, iface),
		}
		if trusted {
			r.Detail = fmt.Sprintf("ufw is active and allows traffic on %s", iface)
		} else {
			r.Detail = fmt.Sprintf("ufw is active and does not allow %s, so mesh traffic is being dropped", iface)
		}
		return r

	case nftablesFiltering():
		// An accept in a table of makima's own would not override a drop in
		// somebody else's, so the rule goes into each chain that drops, at
		// the top, tagged so it can be found and taken out again (nft.go).
		drops, mine, _ := nftState()
		trusted := len(missing(drops, mine, nftIfaceComment(iface))) == 0
		r := Report{
			Backend:   BackendNFTables,
			Active:    true,
			Trusted:   trusted,
			Automatic: true,
			Manual: fmt.Sprintf(
				"sudo nft insert rule inet filter input iifname \"%s\" accept", iface),
		}
		if trusted {
			r.Detail = fmt.Sprintf("nftables is filtering and accepts traffic on %s", iface)
		} else {
			r.Detail = fmt.Sprintf("nftables drops input by default and %s is not accepted, so mesh traffic is being dropped", iface)
		}
		return r

	case iptablesFiltering():
		trusted := iptablesAllows(iface)
		r := Report{
			Backend:   BackendIPTables,
			Active:    true,
			Trusted:   trusted,
			Automatic: true,
			Manual:    fmt.Sprintf("sudo iptables -I INPUT 1 -i %s -j ACCEPT", iface),
		}
		if trusted {
			r.Detail = fmt.Sprintf("iptables is filtering and accepts traffic on %s", iface)
		} else {
			r.Detail = fmt.Sprintf("iptables INPUT policy is DROP and %s is not accepted, so mesh traffic is being dropped", iface)
		}
		return r
	}

	return Report{
		Backend: BackendNone,
		Active:  false,
		Trusted: true,
		Detail:  "no host firewall is filtering; nothing to configure",
	}
}

func firewallAllow(iface string, b Backend) error {
	switch b {
	case BackendFirewalld:
		if err := run("firewall-cmd", "--permanent", "--zone=trusted", "--add-interface="+iface); err != nil {
			return err
		}
		// Without the reload the permanent rule sits in the config file and
		// the running firewall never sees it, which is the classic way this
		// looks applied and is not.
		return run("firewall-cmd", "--reload")

	case BackendUFW:
		if err := run("ufw", "allow", "in", "on", iface); err != nil {
			return err
		}
		// Also the forward path, so an approved subnet route or exit node
		// works without a second visit here.
		return run("ufw", "route", "allow", "in", "on", iface)

	case BackendNFTables:
		drops, mine, err := nftState()
		if err != nil {
			return err
		}
		c := nftIfaceComment(iface)
		for _, ch := range missing(drops, mine, c) {
			if err := run("nft", nftInsertArgs(ch, []string{"iifname", `"` + iface + `"`}, c)...); err != nil {
				return err
			}
		}
		return nil

	case BackendIPTables:
		if iptablesAllows(iface) {
			return nil
		}
		// Inserted at position 1 rather than appended: a DROP earlier in the
		// chain would match first, and appending would leave the rule present
		// and useless.
		return run("iptables", "-I", "INPUT", "1", "-i", iface, "-j", "ACCEPT")
	}
	return fmt.Errorf("netcfg: cannot configure %s automatically", b)
}

// nftState reads the live ruleset.
func nftState() ([]nftChain, []nftRule, error) {
	out, err := combined("nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, nil, fmt.Errorf("list the nftables ruleset: %w", err)
	}
	return parseNFT([]byte(out))
}

// nftDelete takes out makima's rules with one comment, by handle.
func nftDelete(comment string) error {
	_, mine, err := nftState()
	if err != nil {
		return err
	}
	var firstErr error
	for _, r := range mine {
		if r.Comment != comment {
			continue
		}
		if err := run("nft", "delete", "rule", r.Family, r.Table, r.Name, "handle", strconv.Itoa(r.Handle)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func firewallReset(iface string, b Backend) error {
	switch b {
	case BackendFirewalld:
		if err := run("firewall-cmd", "--permanent", "--zone=trusted", "--remove-interface="+iface); err != nil {
			return err
		}
		return run("firewall-cmd", "--reload")

	case BackendUFW:
		_ = run("ufw", "--force", "delete", "allow", "in", "on", iface)
		_ = run("ufw", "--force", "delete", "route", "allow", "in", "on", iface)
		return nil

	case BackendNFTables:
		return nftDelete(nftIfaceComment(iface))

	case BackendIPTables:
		// Delete by specification rather than by index. Deleting by index is
		// how a daemon removes somebody else's rule after the chain has
		// shifted underneath it.
		_ = run("iptables", "-D", "INPUT", "-i", iface, "-j", "ACCEPT")
		return nil
	}
	return nil
}

func firewalldRunning() bool {
	if !have("firewall-cmd") {
		return false
	}
	// --state exits non-zero when not running, and prints the answer either
	// way, so the output is what to trust.
	return strings.Contains(output("firewall-cmd", "--state"), "running")
}

func ufwActive() bool {
	if !have("ufw") {
		return false
	}
	return strings.Contains(output("ufw", "status"), "Status: active")
}

func ufwAllows(iface string) bool {
	out := output("ufw", "status")
	return strings.Contains(out, "on "+iface)
}

// nftablesFiltering reports a bare nftables ruleset with a drop policy.
//
// Only counts when there is no manager on top: firewalld and ufw both drive
// nftables on a modern distribution, and finding one of those is the answer.
// A hook input chain whose policy is drop is the thing that silently eats
// tunnel traffic; a ruleset that exists but accepts by default does not, and
// iptables-nft's chains are the iptables backend's to handle.
func nftablesFiltering() bool {
	if !have("nft") {
		return false
	}
	drops, _, err := nftState()
	return err == nil && len(drops) > 0
}

func iptablesFiltering() bool {
	if !have("iptables") {
		return false
	}
	out := output("iptables", "-S", "INPUT")
	return strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-P INPUT REJECT")
}

func iptablesAllows(iface string) bool {
	out := output("iptables", "-S", "INPUT")
	return strings.Contains(out, "-i "+iface+" -j ACCEPT")
}

// OpenPort lets one port in through the host firewall and says which firewall
// it told, or "" when nothing is filtering. It is how the network's server
// and WireGuard's own UDP port become reachable on a machine that filters its
// LAN — which, left alone, looks exactly like a machine that is down.
//
// firewalld and ufw are told the way they expect, and remember it. In a bare
// nftables or iptables ruleset the accept goes at the top of the chain that
// drops, tagged "makima <proto> <port>" so it is added once and can be found
// again; dist/uninstall.sh takes those out. They last until the ruleset is
// next reloaded, and makima puts them back each time it starts.
func OpenPort(proto string, port int) (string, error) {
	spec := fmt.Sprintf("%d/%s", port, proto)
	comment := nftPortComment(proto, port)
	switch {
	case firewalldRunning():
		if runOK("firewall-cmd", "--query-port="+spec) {
			return "firewalld", nil
		}
		if err := run("firewall-cmd", "--permanent", "--add-port="+spec); err != nil {
			return "", err
		}
		return "firewalld", run("firewall-cmd", "--reload")
	case ufwActive():
		return "ufw", run("ufw", "allow", spec)
	case nftablesFiltering():
		drops, mine, err := nftState()
		if err != nil {
			return "", err
		}
		for _, c := range missing(drops, mine, comment) {
			if err := run("nft", nftInsertArgs(c, []string{proto, "dport", strconv.Itoa(port)}, comment)...); err != nil {
				return "", err
			}
		}
		return "nftables", nil
	case iptablesFiltering():
		rule := []string{"INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-m", "comment", "--comment", comment, "-j", "ACCEPT"}
		if runOK("iptables", append([]string{"-C"}, rule...)...) {
			return "iptables", nil
		}
		return "iptables", run("iptables", append([]string{"-I", rule[0], "1"}, rule[1:]...)...)
	}
	return "", nil
}
