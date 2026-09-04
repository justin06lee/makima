package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/localapi"
)

func TestPeerAddressResolvesByName(t *testing.T) {
	st := localapi.Status{
		Domain: "makima.net",
		Peers: []localapi.PeerInfo{
			{Name: "desktop", Address: netip.MustParseAddr("100.64.0.2"), Online: true, Path: "direct 1.2.3.4:1"},
		},
	}

	for _, name := range []string{"desktop", "desktop.makima.net"} {
		got, err := peerAddress(st, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.String() != "100.64.0.2" {
			t.Errorf("%s resolved to %s", name, got)
		}
	}
}

// A machine that has not been named is not a dead end: an address typed
// directly has to work.
func TestPeerAddressAcceptsALiteralAddress(t *testing.T) {
	got, err := peerAddress(localapi.Status{}, "100.64.0.9")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "100.64.0.9" {
		t.Errorf("got %s", got)
	}
}

// A typo should list what does exist, because the next thing anybody does is
// try to remember the name.
func TestPeerAddressListsWhatItCanSee(t *testing.T) {
	st := localapi.Status{Peers: []localapi.PeerInfo{
		{Name: "desktop"}, {Name: "nas"},
	}}

	_, err := peerAddress(st, "destkop")
	if err == nil {
		t.Fatal("a misspelt name resolved")
	}
	if !strings.Contains(err.Error(), "desktop") || !strings.Contains(err.Error(), "nas") {
		t.Errorf("the error does not list the machines: %v", err)
	}
}

func TestPeerAddressSaysWhenThereAreNoPeers(t *testing.T) {
	_, err := peerAddress(localapi.Status{}, "desktop")
	if err == nil {
		t.Fatal("a name resolved against an empty mesh")
	}
	if !strings.Contains(err.Error(), "no peers") {
		t.Errorf("the error does not say the mesh is empty: %v", err)
	}
}

func TestProgressBarReachesAHundred(t *testing.T) {
	if got := progressBar(50, 100); !strings.Contains(got, "50%") {
		t.Errorf("halfway rendered as %q", got)
	}
	done := progressBar(100, 100)
	if !strings.Contains(done, "100%") {
		t.Errorf("a finished transfer rendered as %q", done)
	}
	// A bar of unknown length still has to say something useful.
	if got := progressBar(1024, 0); !strings.Contains(got, "KiB") {
		t.Errorf("an unknown total rendered as %q", got)
	}
}

func TestHumanSize(t *testing.T) {
	cases := map[int64]string{
		0:               "0 B",
		512:             "512 B",
		1024:            "1.0 KiB",
		1024 * 1024:     "1.0 MiB",
		3 * 1024 * 1024: "3.0 MiB",
	}
	for n, want := range cases {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", n, got, want)
		}
	}
}
