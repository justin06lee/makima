package netcfg

import (
	"fmt"
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
		// The one case makima will not touch. In nftables every table sees
		// every packet and any table may drop it, so an accept rule in a table
		// of ours would not override somebody else's drop. Installing one
		// would look like a fix and change nothing.
		return Report{
			Backend:   BackendNFTables,
			Active:    true,
			Trusted:   false,
			Automatic: false,
			Manual: fmt.Sprintf(
				"sudo nft insert rule inet filter input iifname \"%s\" accept", iface),
			Detail: "a bare nftables ruleset is filtering; makima will not edit it, because an accept rule in a separate table would not override a drop in yours",
		}

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
func nftablesFiltering() bool {
	if !have("nft") {
		return false
	}
	out := output("nft", "list", "ruleset")
	if out == "" {
		return false
	}
	// A hook input chain whose policy is drop is the thing that silently eats
	// tunnel traffic. A ruleset that exists but accepts by default does not.
	return strings.Contains(out, "hook input") && strings.Contains(out, "policy drop")
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

// OpenPort lets one port in through the host firewall, where makima can do
// that the way the firewall's own manager expects — firewalld or ufw — and
// says which. It is how the network's server becomes reachable on a machine
// that filters its LAN. Plain nftables and iptables rules are left alone for
// the reason firewallStatus gives, and the error says exactly what to add.
func OpenPort(proto string, port int) (string, error) {
	spec := fmt.Sprintf("%d/%s", port, proto)
	switch {
	case firewalldRunning():
		if err := run("firewall-cmd", "--permanent", "--add-port="+spec); err != nil {
			return "", err
		}
		return "firewalld", run("firewall-cmd", "--reload")
	case ufwActive():
		return "ufw", run("ufw", "allow", spec)
	case nftablesFiltering():
		return "", fmt.Errorf("this machine's nftables rules may drop %s, and makima does not edit them — allow it with: sudo nft insert rule inet filter input %s dport %d accept", spec, proto, port)
	case iptablesFiltering():
		return "", fmt.Errorf("this machine's iptables rules may drop %s, and makima does not edit them — allow it with: sudo iptables -I INPUT -p %s --dport %d -j ACCEPT", spec, proto, port)
	}
	return "", nil
}
