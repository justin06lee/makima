package portmap

import (
	"net/netip"
	"os/exec"
	"strings"
)

// DefaultRoute finds the default router on macOS, and the interface it is
// reached through.
//
// Parsing `route -n get default` rather than reading the routing socket
// directly. The syscall route is not much harder, but it is a large amount of
// platform-specific struct decoding for a value this package needs once a
// minute, and the command's output format has been stable for decades.
//
// It asks for the default route itself — destination and mask both zero —
// not for the route to 0.0.0.0, so the two halves an exit node installs into
// the tunnel do not answer in its place.
func DefaultRoute() (Route, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return Route{}, ErrNoGateway
	}
	return parseRouteGet(string(out))
}

func parseRouteGet(out string) (Route, error) {
	var r Route
	for _, line := range strings.Split(out, "\n") {
		field, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(field) {
		case "gateway":
			if addr, err := netip.ParseAddr(value); err == nil && addr.Is4() {
				r.Gateway = addr
			}
		case "interface":
			r.Interface = value
		}
	}
	if !r.Gateway.IsValid() {
		return Route{}, ErrNoGateway
	}
	return r, nil
}
