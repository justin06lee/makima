package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/localapi"
)

// A machine at home that is not the server: the server is the peer reached
// directly at the server's address, and every step names it.
func TestDuckFindsTheServersMachine(t *testing.T) {
	st := localapi.Status{
		Managed: true,
		Server:  "http://192.168.1.253:8081",
		Node:    localapi.NodeInfo{Name: "justin06lee"},
		Peers: []localapi.PeerInfo{
			{Name: "Huiyuns-MacBook-Air-3.local", Path: "direct 192.168.1.199:51820"},
			{Name: "tenet", Path: "direct 192.168.1.253:41641"},
		},
	}
	p, err := planDuck(st, []netip.Addr{netip.MustParseAddr("192.168.1.148")})
	if err != nil {
		t.Fatal(err)
	}
	if p.Server != "tenet" || p.Here {
		t.Errorf("server %q, here %v; want tenet, elsewhere", p.Server, p.Here)
	}
	if !p.Private || p.Port != 8081 || p.TunnelPort != 41641 {
		t.Errorf("private %v, port %d, tunnel %d; want private, 8081, 41641", p.Private, p.Port, p.TunnelPort)
	}

	var out strings.Builder
	p.write(&out)
	for _, want := range []string{
		"https://www.duckdns.org",
		"makima possess tenet",
		"sudo makima-server ddns set -name NAME",
		"TCP 8081",
		"UDP 41641",
		"→ 192.168.1.253",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the walk-through never says %q:\n%s", want, out.String())
		}
	}
}

// On the server itself, step 3 happens here, with nothing to possess.
func TestDuckOnTheServerSaysHere(t *testing.T) {
	st := localapi.Status{
		Managed: true,
		Server:  "http://192.168.1.253:8081",
		Node:    localapi.NodeInfo{Name: "tenet"},
	}
	p, err := planDuck(st, []netip.Addr{netip.MustParseAddr("192.168.1.253")})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Here || p.Server != "tenet" {
		t.Fatalf("here %v, server %q; want here, tenet", p.Here, p.Server)
	}

	var out strings.Builder
	p.write(&out)
	if strings.Contains(out.String(), "makima possess") {
		t.Errorf("on the server, it says to possess another machine:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "Give both to the server, here:") {
		t.Errorf("step 3 does not say it happens here:\n%s", out.String())
	}
}

// Once the server keeps a name, the first three steps are done, and say so
// with the name rather than asking for one again.
func TestDuckMarksANameAlreadySetAsDone(t *testing.T) {
	st := localapi.Status{
		Managed:    true,
		Server:     "http://192.168.1.253:8081",
		ServerURLs: []string{"http://192.168.1.253:8081", "http://tenet-home.duckdns.org:8081"},
		Node:       localapi.NodeInfo{Name: "justin06lee"},
		Peers:      []localapi.PeerInfo{{Name: "tenet", Path: "direct 192.168.1.253:51820"}},
	}
	p, err := planDuck(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Duck != "tenet-home.duckdns.org" {
		t.Fatalf("duck %q, want tenet-home.duckdns.org", p.Duck)
	}

	var out strings.Builder
	p.write(&out)
	if !strings.Contains(out.String(), "✓ 1–3.") || strings.Contains(out.String(), "Get a name") {
		t.Errorf("a name already set is not shown as done:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "TCP 8081") {
		t.Errorf("the router step is missing once the name is set:\n%s", out.String())
	}
}
