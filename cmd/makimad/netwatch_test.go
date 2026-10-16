package main

import (
	"net/netip"
	"testing"
	"time"
)

func aps(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddrPort(s).Addr())
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

// st is a network state from interface addresses with their prefix lengths.
func st(pfxs ...string) netState {
	out := make([]netip.Prefix, 0, len(pfxs))
	for _, p := range pfxs {
		out = append(out, netip.MustParsePrefix(p))
	}
	return stateOf(out)
}

var (
	jetsonHome = st("192.168.1.213/24", "2600:1702:891b:aa00::39/64", "2600:1702:891b:aa00:16d:4d00:2c8f:b723/64")
	homeV6Only = st("2600:1702:891b:aa00::39/64")
	homeV4Only = st("192.168.1.213/24")
	hotspot    = st("172.20.10.2/28")
	hotspotV6  = st("172.20.10.2/28", "2600:1010:b228:a823:834:e0f2:879b:ed1e/64")
)

type look struct {
	state netState
	after time.Duration // since the tracker started
	want  netMove
}

func walk(t *testing.T, from netState, looks ...look) {
	t.Helper()
	start := time.Unix(1_790_000_000, 0)
	tr := newNetTracker(from)
	for i, l := range looks {
		if got := tr.observe(l.state, start.Add(l.after)); got != l.want {
			t.Errorf("look %d (%s at +%s): %v, want %v", i, l.state, l.after, got, l.want)
		}
	}
}

// The Jetson's Wi-Fi drop, as its log shows one: IPv4 goes, IPv6 stays, IPv4
// comes back with the same address. Three "network changed" resets, each
// dropping every path and redialling the relay over tor; now one quiet
// "back", which keeps them.
func TestAWiFiDropOnTheSameNetworkIsNotAMove(t *testing.T) {
	walk(t, jetsonHome,
		look{homeV6Only, 3 * time.Second, netDown},
		look{homeV6Only, 6 * time.Second, netSame},
		look{homeV4Only, 40 * time.Second, netDown},
		look{jetsonHome, 43 * time.Second, netBack},
		look{jetsonHome, 46 * time.Second, netSame},
	)
}

// Gone altogether for a moment, back on the same network: still not a move.
func TestABriefOutageIsNotAMove(t *testing.T) {
	walk(t, jetsonHome,
		look{st(), 3 * time.Second, netAway},
		look{jetsonHome, 30 * time.Second, netBack},
	)
}

// The DHCP server handing out another address on the same subnet — which the
// Jetson's did eight times in two days — keeps the network, and with it the
// paths, but the address and its NAT mapping are new.
func TestANewAddressOnTheSameNetworkIsARenumber(t *testing.T) {
	walk(t, st("192.168.1.212/24", "2600:1702:891b:aa00::39/64"),
		look{homeV6Only, 3 * time.Second, netDown},
		look{st("192.168.1.213/24", "2600:1702:891b:aa00::39/64"), 9 * time.Second, netRenumbered},
	)
	// The subnet says so without IPv6 as well.
	walk(t, st("192.168.1.212/24"),
		look{st(), 3 * time.Second, netAway},
		look{st("192.168.1.213/24"), 9 * time.Second, netRenumbered},
	)
}

// Leaving the house for the phone's hotspot is a move. The hotspot's IPv6
// arriving a second later is more of the same network, not another move.
func TestLeavingTheHouseIsAMove(t *testing.T) {
	walk(t, jetsonHome,
		look{st(), 3 * time.Second, netAway},
		look{hotspot, 6 * time.Second, netMoved},
		look{hotspotV6, 9 * time.Second, netGrew},
	)
	// Straight from one to the other, with no gap seen in between.
	walk(t, jetsonHome, look{hotspot, 3 * time.Second, netMoved})
}

// Gone for long enough to have been carried somewhere else, a network that
// looks the same — two AT&T homes both hand out 192.168.1.x — is not trusted
// to be the same.
func TestALongAbsenceIsAMoveEvenToALookalike(t *testing.T) {
	walk(t, homeV4Only,
		look{st(), 3 * time.Second, netAway},
		look{homeV4Only, 3*time.Second + blipWindow + time.Second, netMoved},
	)
}

// Half a network gone for good settles as a renumber once it has been gone
// longer than any drop: the addresses lost are not coming back.
func TestALastingLossSettles(t *testing.T) {
	walk(t, jetsonHome,
		look{homeV6Only, 3 * time.Second, netDown},
		look{homeV6Only, 6 * time.Second, netSame},
		look{homeV6Only, 3*time.Second + blipWindow + time.Second, netRenumbered},
		look{homeV6Only, 6*time.Second + blipWindow + time.Second, netSame},
	)
}

// A rotated IPv6 privacy address is not a change at all.
func TestAPrivacyRotationIsNoChange(t *testing.T) {
	walk(t, jetsonHome,
		look{st("192.168.1.213/24", "2600:1702:891b:aa00::39/64", "2600:1702:891b:aa00:aaaa:bbbb:cccc:dddd/64"), 3 * time.Second, netSame},
	)
}
