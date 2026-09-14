//go:build !linux && !darwin

package netcfg

// Everywhere other than Linux and macOS, makima does not look at the host
// firewall at all.
//
// Reporting "unsupported" rather than "none" keeps the distinction honest: it
// means makima did not look, not that it looked and found nothing.
func firewallStatus(iface string) Report {
	return Report{
		Backend:   BackendUnsupported,
		Active:    false,
		Trusted:   true,
		Automatic: false,
		Detail:    "makima does not check the host firewall on this platform",
	}
}

func firewallAllow(iface string, b Backend) error { return nil }
func firewallReset(iface string, b Backend) error { return nil }

// OpenPort has nothing to do where firewallStatus has nothing to configure.
func OpenPort(proto string, port int) (string, error) { return "", nil }
