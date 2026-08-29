package portmap

import (
	"net/netip"
	"os/exec"
	"strings"
)

// Gateway finds the default router on macOS.
//
// Parsing `route -n get default` rather than reading the routing socket
// directly. The syscall route is not much harder, but it is a large amount of
// platform-specific struct decoding for a value this package needs once a
// minute, and the command's output format has been stable for decades.
func Gateway() (netip.Addr, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return netip.Addr{}, ErrNoGateway
	}

	for _, line := range strings.Split(string(out), "\n") {
		field, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.TrimSpace(field) != "gateway" {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		if addr.Is4() {
			return addr, nil
		}
	}
	return netip.Addr{}, ErrNoGateway
}
