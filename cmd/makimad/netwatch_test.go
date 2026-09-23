package main

import (
	"net/netip"
	"testing"
)

func aps(ss ...string) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddrPort(s))
	}
	return out
}

func TestFingerprintNamesNetworksNotAddresses(t *testing.T) {
	home := fingerprint(aps("192.168.1.199:1", "[2600:1702:891b:aa00::28]:1", "[2600:1702:891b:aa00:1c2d:3e4f:5a6b:7c8d]:1"))

	// A new IPv6 privacy address on the same network is not a move.
	rotated := fingerprint(aps("[2600:1702:891b:aa00:9999:8888:7777:6666]:1", "192.168.1.199:1"))
	if rotated != home {
		t.Errorf("a rotated privacy address looked like a move:\n%s\n%s", home, rotated)
	}

	// A café is.
	cafe := fingerprint(aps("10.20.30.40:1"))
	if cafe == home {
		t.Error("changing networks went unnoticed")
	}
	if fingerprint(nil) != "" {
		t.Error("no addresses should fingerprint as empty")
	}
}
