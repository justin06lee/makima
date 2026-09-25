package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/netmap"
)

func TestTailscaleIsFoundWhereverItRuns(t *testing.T) {
	p := netip.MustParsePrefix
	for _, c := range []struct {
		name   string
		ifaces []ifaceAddrs
		want   string
	}{
		{"linux", []ifaceAddrs{{name: "tailscale0", addrs: []netip.Prefix{p("100.101.1.2/32")}, tunnel: true}}, "tailscale0"},
		{"macos, by its IPv6", []ifaceAddrs{{name: "utun3", addrs: []netip.Prefix{p("fd7a:115c:a1e0::5/128")}, tunnel: true}}, "utun3"},
		{"macos, IPv4 only", []ifaceAddrs{{name: "utun5", addrs: []netip.Prefix{p("100.90.1.1/32")}, tunnel: true}}, "utun5"},
		{"not makima's own", []ifaceAddrs{{name: "utun7", addrs: []netip.Prefix{p("100.64.0.3/32")}, tunnel: true}}, ""},
		// A carrier handing out 100.64/10 on Wi-Fi is not Tailscale.
		{"not a CGNAT LAN", []ifaceAddrs{{name: "en0", addrs: []netip.Prefix{p("100.72.5.9/24")}}}, ""},
	} {
		got, ok := tailscaleIface(c.ifaces, "utun7")
		if (c.want != "") != ok || got.name != c.want {
			t.Errorf("%s: found %q (%v), want %q", c.name, got.name, ok, c.want)
		}
	}
}

func fakeLookups(routes map[string]string, names map[string][]netip.Addr) lookups {
	return lookups{
		route: func(_ context.Context, a netip.Addr) (string, error) { return routes[a.String()], nil },
		names: func(_ context.Context, n string) ([]netip.Addr, error) { return names[n], nil },
	}
}

func tsView() tailscaleView {
	return tailscaleView{
		iface:    "utun7",
		self:     netip.MustParseAddr("10.77.0.5"),
		selfName: "Huiyun's MacBook Air",
		domain:   "makima",
		peers: []netmap.Node{{
			Name:      "tenet",
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")},
		}},
	}
}

var ts0 = ifaceAddrs{name: "tailscale0", addrs: []netip.Prefix{netip.MustParsePrefix("100.101.1.2/32")}}

func TestTailscaleBesideMakimaIsFine(t *testing.T) {
	look := fakeLookups(
		map[string]string{"10.77.0.1": "utun7", "1.1.1.1": "en0"},
		map[string][]netip.Addr{"huiyuns-macbook-air.makima": {netip.MustParseAddr("10.77.0.5")}},
	)
	got := tailscaleChecks(context.Background(), ts0, tsView(), look)
	if len(got) != 1 || !got[0].OK {
		t.Errorf("got %+v", got)
	}
}

func TestTailscaleTakingMakimasRoutes(t *testing.T) {
	look := fakeLookups(map[string]string{"10.77.0.1": "tailscale0", "1.1.1.1": "en0"}, nil)
	v := tsView()
	v.domain = ""
	got := tailscaleChecks(context.Background(), ts0, v, look)
	if len(got) != 1 || got[0].OK || !strings.Contains(got[0].Detail, "tenet") || !strings.Contains(got[0].Fix, "accept-routes") {
		t.Errorf("got %+v", got)
	}
}

func TestTailscaleExitNode(t *testing.T) {
	look := fakeLookups(map[string]string{"10.77.0.1": "utun7", "1.1.1.1": "tailscale0"}, nil)
	v := tsView()
	v.domain = ""
	got := tailscaleChecks(context.Background(), ts0, v, look)
	if len(got) != 1 || !got[0].Warning || !strings.Contains(got[0].Fix, "exit-node") {
		t.Errorf("got %+v", got)
	}

	// Using makima's own exit node, the internet going into a tunnel is the
	// point, and is not Tailscale's doing.
	v.exit = true
	if got := tailscaleChecks(context.Background(), ts0, v, look); len(got) != 1 || !got[0].OK {
		t.Errorf("with makima's exit node: %+v", got)
	}
}

func TestTailscaleAnsweringForMakimasNames(t *testing.T) {
	look := fakeLookups(
		map[string]string{"10.77.0.1": "utun7", "1.1.1.1": "en0"},
		map[string][]netip.Addr{}, // nothing comes back for *.makima
	)
	got := tailscaleChecks(context.Background(), ts0, tsView(), look)
	if len(got) != 1 || got[0].OK || !strings.Contains(got[0].Fix, "accept-dns") {
		t.Errorf("got %+v", got)
	}
}
