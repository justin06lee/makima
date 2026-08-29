//go:build !darwin && !linux

package netcfg

import (
	"fmt"
	"net/netip"
	"runtime"
)

// Windows lands with the wintun backend, where addressing goes through the
// driver's own API rather than a command line tool. Until then, fail loudly
// rather than pretending the interface came up.
func setAddr(iface string, addr netip.Addr) error {
	return fmt.Errorf("netcfg: address assignment not implemented on %s", runtime.GOOS)
}

func addRoute(iface string, r netip.Prefix) error {
	return fmt.Errorf("netcfg: route installation not implemented on %s", runtime.GOOS)
}

func delRoute(iface string, r netip.Prefix) error {
	return fmt.Errorf("netcfg: route removal not implemented on %s", runtime.GOOS)
}

func addRouteVia(r netip.Prefix, gateway netip.Addr) error {
	return fmt.Errorf("netcfg: route installation not implemented on %s", runtime.GOOS)
}

func delRouteVia(r netip.Prefix, gateway netip.Addr) error {
	return fmt.Errorf("netcfg: route removal not implemented on %s", runtime.GOOS)
}

func addDefaultViaInterface(iface string) error {
	return fmt.Errorf("netcfg: exit nodes are not implemented on %s", runtime.GOOS)
}

func delDefaultViaInterface(iface string) error { return nil }

func enableForwarding(iface string) error {
	return fmt.Errorf("netcfg: subnet routing is not implemented on %s", runtime.GOOS)
}

func disableForwarding(iface string) error { return nil }
