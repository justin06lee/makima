package main

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/justin06lee/makima/internal/dnsserver"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
)

// Tailscale beside makima.
//
// The two are meant to run together — moving off Tailscale is done a machine
// at a time, with both up — and on makima's own range they share nothing.
// But Tailscale can still take things that are makima's, and each way it can
// looks, from inside makima, like makima being broken:
//
//   - routes: a subnet route Tailscale accepted can cover makima's range. On
//     Linux Tailscale's routing table is consulted before the main one, so it
//     wins even over makima's host routes, and makima's traffic goes into
//     Tailscale.
//   - an exit node: Tailscale sending the machine's internet traffic through
//     one carries makima's own WireGuard packets too, so every other machine
//     is reached through the exit node, and direct paths are found from its
//     address or not at all.
//   - names: Tailscale's DNS settings can answer for everything, *.makima
//     included.
//
// So the doctor asks the kernel and the system resolver — the routing
// table's and the resolver's real answers, after Tailscale has had its say —
// rather than trusting what makima installed.

// tailscaleULA is the IPv6 range Tailscale gives every machine.
var tailscaleULA = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

// tailscaleIface finds Tailscale's interface, if it is running: tailscale0
// on Linux, and on macOS whichever tunnel holds a Tailscale address — its
// IPv6 range, or an address in 100.64.0.0/10 on a tunnel that is not
// makima's own.
func tailscaleIface(ifaces []ifaceAddrs, mine string) (ifaceAddrs, bool) {
	for _, ifc := range ifaces {
		if ifc.name == mine {
			continue
		}
		if ifc.name == "tailscale0" {
			return ifc, true
		}
		for _, p := range ifc.addrs {
			a := p.Addr()
			if tailscaleULA.Contains(a) || (ifc.tunnel && a.Is4() && netcfg.LegacyMeshRange.Contains(a)) {
				return ifc, true
			}
		}
	}
	return ifaceAddrs{}, false
}

// lookups are how the Tailscale checks ask the kernel and the resolver; the
// real ones in the daemon, stand-ins in a test.
type lookups struct {
	route func(context.Context, netip.Addr) (string, error)
	names func(context.Context, string) ([]netip.Addr, error)
}

var systemLookups = lookups{route: netcfg.RouteInterface, names: netcfg.SystemLookup}

// maxRouteChecks bounds how many peers the doctor asks the kernel about:
// one route lookup per peer, and a route that covers one covers the range.
const maxRouteChecks = 4

// tailscaleView is what the Tailscale checks need to know about this node.
type tailscaleView struct {
	iface    string // makima's own interface
	self     netip.Addr
	selfName string
	domain   string // empty when mesh names are off here
	peers    []netmap.Node
	exit     bool // makima's own exit node is in use
}

// tailscaleChecks are the doctor's findings about a Tailscale that is
// running here, ts being its interface. One check when all is well, one per
// problem otherwise.
func tailscaleChecks(ctx context.Context, ts ifaceAddrs, v tailscaleView, look lookups) []localapi.Check {
	where := ts.name
	for _, p := range ts.addrs {
		if a := p.Addr(); a.Is4() {
			where = fmt.Sprintf("%s (%s)", ts.name, a)
			break
		}
	}

	var out []localapi.Check

	// Routes to makima's own machines.
	var taken []string
	for _, p := range v.peers[:min(len(v.peers), maxRouteChecks)] {
		a, err := p.Addr()
		if err != nil {
			continue
		}
		if ifc, err := look.route(ctx, a); err == nil && ifc == ts.name {
			taken = append(taken, fmt.Sprintf("%s (%s)", p.Name, a))
		}
	}
	if len(taken) > 0 {
		rng := netcfg.MeshRange
		if r, ok := netcfg.MeshRangeOf(v.self); ok {
			rng = r
		}
		out = append(out, localapi.Check{
			Name: "Tailscale",
			Detail: fmt.Sprintf("traffic for %s goes out Tailscale's %s, not makima's %s — a route Tailscale accepted covers %s, and takes makima's traffic with it",
				strings.Join(taken, ", "), ts.name, v.iface, rng),
			Fix: "tailscale set --accept-routes=false   # or stop the tailnet advertising a route over " + rng.String(),
		})
	}

	// An exit node, which only matters when makima is not routing the
	// internet itself.
	if !v.exit {
		if ifc, err := look.route(ctx, netip.MustParseAddr("1.1.1.1")); err == nil && ifc == ts.name {
			out = append(out, localapi.Check{
				Name:    "Tailscale",
				Warning: true,
				Detail:  "Tailscale is sending this machine's internet traffic through an exit node, makima's own with it: the other machines are reached through the exit node, and direct paths are found from its address or not at all",
				Fix:     "tailscale set --exit-node=   # or use a makima exit node: makima set -exit-node NAME",
			})
		}
	}

	// Names. Asked for this machine's own, which the resolver here can
	// only get wrong if something other than makima is answering.
	if v.domain != "" && v.self.IsValid() && v.selfName != "" {
		name := dnsserver.Label(v.selfName) + "." + v.domain
		if got, err := look.names(ctx, name); err == nil && !slices.Contains(got, v.self) {
			out = append(out, localapi.Check{
				Name:   "Tailscale",
				Detail: fmt.Sprintf("%s does not resolve to %s through this machine's resolver while Tailscale runs — its DNS settings are answering for *.%s in makima's place", name, v.self, v.domain),
				Fix:    "tailscale set --accept-dns=false",
			})
		}
	}

	if len(out) == 0 {
		out = append(out, localapi.Check{
			Name:   "Tailscale",
			OK:     true,
			Detail: fmt.Sprintf("running beside makima on %s; the routes to this network's machines and its names are makima's", where),
		})
	}
	return out
}
