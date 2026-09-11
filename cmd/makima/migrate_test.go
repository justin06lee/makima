package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/invite"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

func node(server string, sk key.Public, addr string) *conf.File {
	f := &conf.File{LoginServer: server, ServerKey: sk}
	if addr != "" {
		f.Self = netmap.Node{Addresses: []netip.Prefix{netip.MustParsePrefix(addr + "/32")}}
	}
	return f
}

// What a machine already on a network does when the move asks it to join one.
// The case that prompted this: a Mac left on an earlier try's network, which
// the move then refused to take anywhere.
func TestJoinDecision(t *testing.T) {
	k1, _ := key.NewPrivate()
	k2, _ := key.NewPrivate()
	tenet := invite.Invite{Server: "http://192.168.1.253:8081/", ServerKey: k1.Public()}

	cases := []struct {
		name        string
		f           *conf.File
		holds       bool
		holdsLegacy bool
		want        joinChoice
	}{
		{"already on it", node("http://192.168.1.253:8081", k1.Public(), "10.77.0.4"), false, false, joinRestart},
		{"same address, a new server there", node("http://192.168.1.253:8081", k2.Public(), "10.77.0.4"), false, false, joinLeave},
		{"on another network", node("http://192.168.1.199:8080", k2.Public(), "10.77.0.2"), false, false, joinLeave},
		{"holds another network", node("http://192.168.1.199:8080", k2.Public(), "10.77.0.1"), true, false, joinRefuse},
		{"holds one from an older makima", node("http://192.168.1.199:8080", k2.Public(), "100.64.0.1"), true, true, joinLeave},
		{"on this network, from an older makima", node("http://192.168.1.253:8081", k1.Public(), "100.64.0.2"), false, false, joinLeave},
	}
	for _, c := range cases {
		if got := joinDecision(c.f, tenet, c.holds, c.holdsLegacy); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLegacyRange(t *testing.T) {
	if !onLegacyRange(node("", key.Public{}, "100.64.0.3")) || onLegacyRange(node("", key.Public{}, "10.77.0.3")) || onLegacyRange(node("", key.Public{}, "")) {
		t.Fatal("onLegacyRange")
	}

	dir := t.TempDir()
	old := filepath.Join(dir, "old.json")
	os.WriteFile(old, []byte(`{"prefix": "100.64.0.0/10", "next_id": 3}`), 0o600)
	cur := filepath.Join(dir, "new.json")
	os.WriteFile(cur, []byte(`{"prefix": "10.77.0.0/16"}`), 0o600)
	if !serverStateOnLegacyRange(old) || serverStateOnLegacyRange(cur) || serverStateOnLegacyRange(filepath.Join(dir, "none")) {
		t.Fatal("serverStateOnLegacyRange")
	}
}
