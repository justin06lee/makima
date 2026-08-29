package netcfg

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

// resolverDir is macOS's split-DNS mechanism.
//
// A file named after a domain in /etc/resolver makes the system resolver send
// queries for that domain, and only that domain, to the listed nameserver.
// It is the one piece of macOS network configuration that is a plain text file
// with a documented format, and it needs no scutil, no daemon restart, and no
// entitlement — the resolver picks it up on the next lookup.
const resolverDir = "/etc/resolver"

func setResolver(iface, domain string, server netip.Addr) error {
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", resolverDir, err)
	}

	// search_order keeps this file below anything an administrator has set up
	// by hand for the same domain, so makima never silently wins a conflict it
	// did not know about.
	body := fmt.Sprintf("# Managed by makima. Removed when the daemon exits.\nnameserver %s\nsearch_order 1\n", server)

	path := filepath.Join(resolverDir, domain)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func clearResolver(iface, domain string) error {
	if domain == "" {
		return nil
	}
	err := os.Remove(filepath.Join(resolverDir, domain))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
