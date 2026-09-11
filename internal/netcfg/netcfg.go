// Package netcfg assigns addresses and routes to the TUN interface.
//
// wireguard-go hands you a working tunnel and nothing else — it never touches
// the host's network configuration. Somebody has to tell the OS "this
// interface owns 10.77.0.3, and these prefixes go down it", and that somebody
// is unavoidably per-platform. This package is that seam.
package netcfg

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// MeshRange is the address space makima hands out.
//
// Its own, and not Tailscale's 100.64.0.0/10, so the two can run on one
// machine at once. Sharing Tailscale's range meant they could not: on Linux
// Tailscale drops every packet from 100.64.0.0/10 that did not arrive on its
// own interface, so makima only worked with Tailscale stopped — and moving off
// Tailscale had to be a switch-over instead of something added beside it.
//
// A /16 in the middle of 10/8, away from the ranges that are taken by
// default: 10.0–10.1 by home routers and cloud VPCs, 10.42–10.43 by k3s,
// 10.96 by Kubernetes services, 10.128 and up by cloud regions, 10.211 by
// Parallels. Only /32 host routes are installed, so even a LAN that happens
// to use it loses only the few addresses peers actually hold.
var MeshRange = netip.MustParsePrefix("10.77.0.0/16")

// LegacyMeshRange is where makima allocated before it had a range of its own.
// Networks started then keep their addresses and keep working; they just
// cannot share a Linux machine with a running Tailscale.
var LegacyMeshRange = netip.MustParsePrefix("100.64.0.0/10")

// IsMeshAddr reports whether an address is one makima hands out, now or
// before. 100.64.0.0/10 is also Tailscale's, so it counts as somebody's
// tunnel either way.
func IsMeshAddr(a netip.Addr) bool {
	a = a.Unmap()
	return MeshRange.Contains(a) || LegacyMeshRange.Contains(a)
}

// MeshRangeOf is the range a mesh address came from.
func MeshRangeOf(a netip.Addr) (netip.Prefix, bool) {
	a = a.Unmap()
	switch {
	case MeshRange.Contains(a):
		return MeshRange, true
	case LegacyMeshRange.Contains(a):
		return LegacyMeshRange, true
	}
	return netip.Prefix{}, false
}

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

// combined runs a command and returns its output whether or not it succeeded.
//
// Distinct from run, which folds output into an error. Detection needs to read
// what a command said even when it exited non-zero, because "inactive" is
// routinely reported that way.
func combined(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// have reports whether a command exists on this machine.
func have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
