package netcfg

import (
	"fmt"
	"strings"
	"sync"
)

// Firewall makes the host willing to accept traffic that arrives through the
// tunnel.
//
// A tunnel delivers packets to the host's network stack like any other
// interface, so a host firewall filters them like any other traffic. That is
// the second half of why a home server is unreachable: the service was bound
// to localhost, and even after that is solved, firewalld or ufw drops the
// connection on the way in. Neither failure says anything useful — both look
// like the network is broken.
//
// What is installed is narrow: accept input arriving on the tunnel interface,
// and nothing else. It opens no port to the LAN and no port to the internet.
// Traffic can only arrive on that interface after WireGuard has authenticated
// it, so "trust the tunnel" is not a weakening of the firewall — it is a
// statement that cryptographic authentication is a stronger admission check
// than a port number.
type Firewall struct {
	iface string

	mu      sync.Mutex
	applied Backend
}

// Backend is the host firewall in use.
type Backend string

const (
	// BackendNone means nothing is filtering, so there is nothing to do.
	BackendNone Backend = "none"

	// BackendFirewalld is the default on Fedora and common on Arch with GNOME.
	BackendFirewalld Backend = "firewalld"

	// BackendUFW is Ubuntu's.
	BackendUFW Backend = "ufw"

	// BackendIPTables is a bare iptables ruleset with no manager on top.
	BackendIPTables Backend = "iptables"

	// BackendNFTables is a bare nftables ruleset.
	//
	// The one case that cannot be fixed automatically, and the reason this is a
	// distinct value rather than folded into iptables. In nftables every table
	// sees every packet, so an accept in a table makima owns does not override
	// a drop in a table somebody else owns. Inserting a rule would look like it
	// worked and change nothing. Reporting the rule to add is the honest
	// answer.
	BackendNFTables Backend = "nftables"

	// BackendUnsupported is a platform where none of this applies.
	BackendUnsupported Backend = "unsupported"
)

// Report describes the firewall and what, if anything, needs doing.
type Report struct {
	Backend Backend `json:"backend"`

	// Active is whether the firewall is actually filtering. An installed but
	// stopped firewalld is not a problem.
	Active bool `json:"active"`

	// Trusted is whether the tunnel interface is already allowed.
	Trusted bool `json:"trusted"`

	// Automatic reports whether makima can fix this itself.
	Automatic bool `json:"automatic"`

	// Manual is the exact command to run when it cannot.
	Manual string `json:"manual,omitempty"`

	// Detail explains the state in a sentence.
	Detail string `json:"detail"`
}

// OK reports whether the tunnel will not be filtered.
func (r Report) OK() bool { return !r.Active || r.Trusted }

// NewFirewall builds one for a tunnel interface.
func NewFirewall(iface string) *Firewall { return &Firewall{iface: iface} }

// Status inspects the host firewall without changing anything.
func (f *Firewall) Status() Report { return firewallStatus(f.iface) }

// Allow makes the firewall accept traffic on the tunnel interface.
//
// Idempotent, and a no-op when nothing is filtering. Returns the report so a
// caller can say what it did rather than claiming success generically.
func (f *Firewall) Allow() (Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	r := firewallStatus(f.iface)
	if r.OK() {
		return r, nil
	}
	if !r.Automatic {
		return r, fmt.Errorf(
			"makima cannot configure %s safely.\nrun this yourself:\n  %s",
			r.Backend, r.Manual)
	}

	if err := firewallAllow(f.iface, r.Backend); err != nil {
		return r, err
	}
	f.applied = r.Backend

	after := firewallStatus(f.iface)
	return after, nil
}

// Reset removes what Allow installed.
//
// Only what this process installed, and only for the backend it installed it
// with. A daemon that tore down firewall rules it did not create would be a
// far worse thing to run than one that occasionally leaves one behind.
func (f *Firewall) Reset() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.applied == "" {
		return nil
	}
	err := firewallReset(f.iface, f.applied)
	f.applied = ""
	return err
}

// ResetBackend removes the rule for a named backend, for the CLI's use when no
// daemon is running to remember what it did.
func ResetBackend(iface string, b Backend) error { return firewallReset(iface, b) }

// runOK reports whether a command succeeded, discarding its output.
//
// Detection asks questions whose failure *is* the answer — "is firewalld
// running" fails when it is not — so an error here is information rather than
// a problem.
func runOK(name string, args ...string) bool { return run(name, args...) == nil }

// output runs a command and returns its combined output, empty on failure.
func output(name string, args ...string) string {
	out, err := combined(name, args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
