//go:build !linux

package netcfg

// macOS does not filter inbound traffic on a utun interface by default, and
// the application firewall it does ship judges by application rather than by
// port or interface — so there is nothing here for makima to configure, and
// nothing it could configure that would help.
//
// Reporting "unsupported" rather than "none" keeps the distinction honest: it
// means makima did not look, not that it looked and found nothing.
func firewallStatus(iface string) Report {
	return Report{
		Backend:   BackendUnsupported,
		Active:    false,
		Trusted:   true,
		Automatic: false,
		Detail:    "no host firewall configuration is needed on this platform",
	}
}

func firewallAllow(iface string, b Backend) error { return nil }
func firewallReset(iface string, b Backend) error { return nil }

// OpenPort has nothing to do where firewallStatus has nothing to configure.
func OpenPort(proto string, port int) (string, error) { return "", nil }
