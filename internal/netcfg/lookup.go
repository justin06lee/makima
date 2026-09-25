package netcfg

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// ErrNoLookup is a platform, or a machine, without the tool a lookup needs.
var ErrNoLookup = errors.New("this machine has no way to ask that")

// RouteInterface asks the kernel which interface a packet for dst would
// leave by — the routing table's actual answer, after every other VPN's
// routes and rules have had their say, not what makima installed.
func RouteInterface(ctx context.Context, dst netip.Addr) (string, error) {
	return routeInterface(ctx, dst)
}

// SystemLookup resolves a name the way every other program on the machine
// would, through the system's own resolver, and returns its IPv4 addresses.
func SystemLookup(ctx context.Context, name string) ([]netip.Addr, error) {
	return systemLookup(ctx, name)
}

// lookupOutput runs a lookup tool with a deadline, since both are asked from the
// doctor, which somebody is waiting on.
func lookupOutput(ctx context.Context, name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", ErrNoLookup
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

// parseRouteGet reads the interface from macOS's `route -n get`.
func parseRouteGet(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if field, value, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && strings.TrimSpace(field) == "interface" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// parseIPRouteGet reads the interface from Linux's `ip -o route get`, whose
// one line reads "10.77.0.2 dev makima0 src 10.77.0.1 uid 0".
func parseIPRouteGet(out string) string {
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1]
		}
	}
	return ""
}

// parseDscacheutil reads IPv4 addresses from macOS's
// `dscacheutil -q host -a name`, which answers through the same resolver
// every application uses — /etc/resolver, and whatever a VPN installed.
func parseDscacheutil(out string) []netip.Addr {
	var addrs []netip.Addr
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		if field, value, ok := strings.Cut(strings.TrimSpace(s.Text()), ":"); ok && strings.TrimSpace(field) == "ip_address" {
			if a, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil && a.Is4() {
				addrs = append(addrs, a)
			}
		}
	}
	return addrs
}

// parseGetent reads addresses from Linux's `getent ahostsv4`, which goes
// through NSS — systemd-resolved included — like every application does.
func parseGetent(out string) []netip.Addr {
	var addrs []netip.Addr
	seen := map[netip.Addr]bool{}
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 {
			continue
		}
		if a, err := netip.ParseAddr(fields[0]); err == nil && a.Is4() && !seen[a] {
			seen[a] = true
			addrs = append(addrs, a)
		}
	}
	return addrs
}
