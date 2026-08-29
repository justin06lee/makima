// Package netcfg assigns addresses and routes to the TUN interface.
//
// wireguard-go hands you a working tunnel and nothing else — it never touches
// the host's network configuration. Somebody has to tell the OS "this
// interface owns 100.64.0.3, and these prefixes go down it", and that somebody
// is unavoidably per-platform. This package is that seam.
package netcfg

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// CGNATRange is the address space makima hands out, matching Tailscale's
// choice of 100.64.0.0/10. It is RFC 6598 carrier-grade NAT space: routable
// enough to be useful, reserved enough that it almost never collides with a
// home or office LAN the way 10/8 and 192.168/16 constantly do.
var CGNATRange = netip.MustParsePrefix("100.64.0.0/10")

// Router owns one interface's addresses and routes.
//
// It tracks what it installed so a changing netmap can be applied as a diff.
// Reinstalling every route on every update would be simpler, but adding a
// route that already exists is an error on macOS and a no-op on Linux, so the
// naive version is both noisy and platform-dependent.
type Router struct {
	iface     string
	installed map[netip.Prefix]bool
}

// NewRouter builds a router for an interface.
func NewRouter(iface string) *Router {
	return &Router{iface: iface, installed: make(map[netip.Prefix]bool)}
}

// SetAddr gives the interface its mesh address.
func (r *Router) SetAddr(addr netip.Addr) error {
	if err := setAddr(r.iface, addr); err != nil {
		return fmt.Errorf("assign %s to %s: %w", addr, r.iface, err)
	}
	return nil
}

// Sync makes the installed route set match want, adding and removing the
// difference. Errors are collected rather than returned on the first failure:
// one unroutable peer must not stop the rest of the mesh from coming up.
func (r *Router) Sync(want []netip.Prefix) error {
	desired := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		desired[p] = true
	}

	var problems []string

	for p := range desired {
		if r.installed[p] {
			continue
		}
		if err := addRoute(r.iface, p); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		r.installed[p] = true
	}

	for p := range r.installed {
		if desired[p] {
			continue
		}
		if err := delRoute(r.iface, p); err != nil {
			problems = append(problems, err.Error())
			// Drop it from the map regardless: a route we cannot delete is
			// one we must not believe we still own, or it never gets retried.
		}
		delete(r.installed, p)
	}

	if len(problems) > 0 {
		return fmt.Errorf("route sync: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Routes returns the prefixes currently installed.
func (r *Router) Routes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(r.installed))
	for p := range r.installed {
		out = append(out, p)
	}
	return out
}

// Close removes every route this router installed.
//
// Routes outlive the process that created them. A daemon that exits without
// this leaves the host believing it can still reach mesh addresses down an
// interface that no longer exists, which blackholes them until a reboot — and
// looks like a network fault rather than a leftover.
func (r *Router) Close() error {
	if err := r.Sync(nil); err != nil {
		return err
	}
	return nil
}

// run executes a network configuration command, folding stderr into the error
// so a failure says what the OS actually complained about.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}
