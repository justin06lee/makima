//go:build !darwin && !linux

package netcfg

import (
	"fmt"
	"net/netip"
	"runtime"
)

func setResolver(iface, domain string, server netip.AddrPort) error {
	return fmt.Errorf("netcfg: mesh DNS is not implemented on %s", runtime.GOOS)
}

func clearResolver(iface, domain string) error { return nil }
