package netcfg

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParseRouteLookups(t *testing.T) {
	mac := "   route to: 10.77.0.2\ndestination: 10.77.0.2\n  interface: utun4\n      flags: <UP,HOST,DONE,STATIC>\n"
	if got := parseRouteGet(mac); got != "utun4" {
		t.Errorf("route -n get: %q", got)
	}
	linux := "10.77.0.2 dev tailscale0 table 52 src 100.101.102.103 uid 0 \n    cache "
	if got := parseIPRouteGet(linux); got != "tailscale0" {
		t.Errorf("ip route get: %q", got)
	}
}

func TestParseNameLookups(t *testing.T) {
	mac := "name: tenet.makima\nip_address: 10.77.0.1\n\n"
	if got := parseDscacheutil(mac); !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("10.77.0.1")}) {
		t.Errorf("dscacheutil: %v", got)
	}
	linux := "10.77.0.1       STREAM tenet.makima\n10.77.0.1       DGRAM  \n10.77.0.1       RAW    \n"
	if got := parseGetent(linux); !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("10.77.0.1")}) {
		t.Errorf("getent: %v", got)
	}
}
