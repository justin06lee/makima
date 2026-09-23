package wg

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func mustKey(t *testing.T) key.Private {
	t.Helper()
	k, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func peer(k key.Private, ip string) Peer {
	return Peer{
		PublicKey:  k.Public(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix(ip)},
		Keepalive:  25 * time.Second,
	}
}

// The same configuration twice is no configuration at all: nothing is sent,
// so nothing in the device is disturbed.
func TestDiffOfTheSameConfigIsEmpty(t *testing.T) {
	cfg := Config{PrivateKey: mustKey(t), ListenPort: 51820, Peers: []Peer{peer(mustKey(t), "10.77.0.2/32")}}
	if got := uapiDiff(cfg, cfg.clone(), addrEndpoint); got != "" {
		t.Fatalf("diff of identical configs:\n%s", got)
	}
}

// A new peer elsewhere in the mesh must not touch the peers already there:
// no replace_peers, which would drop every session, and no listen_port, which
// closes and reopens the socket.
func TestDiffTouchesOnlyWhatChanged(t *testing.T) {
	self := mustKey(t)
	a, b, c := mustKey(t), mustKey(t), mustKey(t)
	old := Config{PrivateKey: self, ListenPort: 51820, Peers: []Peer{peer(a, "10.77.0.2/32"), peer(b, "10.77.0.3/32")}}

	moved := peer(b, "10.77.0.3/32")
	moved.AllowedIPs = append(moved.AllowedIPs, netip.MustParsePrefix("192.168.9.0/24"))
	cfg := Config{PrivateKey: self, ListenPort: 51820, Peers: []Peer{peer(a, "10.77.0.2/32"), moved, peer(c, "10.77.0.4/32")}}

	got := uapiDiff(old, cfg, addrEndpoint)
	for _, never := range []string{"replace_peers", "listen_port", "private_key", "public_key=" + a.Public().Hex()} {
		if strings.Contains(got, never) {
			t.Errorf("diff contains %q:\n%s", never, got)
		}
	}
	for _, want := range []string{
		"public_key=" + b.Public().Hex() + "\nupdate_only=true\nreplace_allowed_ips=true\nallowed_ip=10.77.0.3/32\nallowed_ip=192.168.9.0/24\n",
		"public_key=" + c.Public().Hex() + "\nreplace_allowed_ips=true\nallowed_ip=10.77.0.4/32\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("diff is missing\n%s\nin:\n%s", want, got)
		}
	}

	gone := uapiDiff(cfg, Config{PrivateKey: self, ListenPort: 51820, Peers: []Peer{peer(a, "10.77.0.2/32")}}, addrEndpoint)
	if strings.Count(gone, "remove=true") != 2 || strings.Contains(gone, a.Public().Hex()) {
		t.Errorf("removing two peers:\n%s", gone)
	}
}

// Removing a preshared key has to be said out loud: all zeroes is UAPI for
// none, and saying nothing would leave the old key in force.
func TestDiffClearsAPresharedKey(t *testing.T) {
	self, a := mustKey(t), mustKey(t)
	psk, err := key.NewShared()
	if err != nil {
		t.Fatal(err)
	}
	with := peer(a, "10.77.0.2/32")
	with.PresharedKey = psk
	got := uapiDiff(Config{PrivateKey: self, Peers: []Peer{with}}, Config{PrivateKey: self, Peers: []Peer{peer(a, "10.77.0.2/32")}}, addrEndpoint)
	if !strings.Contains(got, "preshared_key="+strings.Repeat("0", 64)) {
		t.Fatalf("diff:\n%s", got)
	}
}

// The regression this guards against, end to end on real wireguard-go devices:
// every netmap used to replace the whole peer set, so a port published on one
// machine made every tunnel in the mesh throw its session away and handshake
// again. A peer that did not change keeps its session through a
// reconfiguration.
func TestReconfiguringKeepsSessionsThatDidNotChange(t *testing.T) {
	binds := bindtest.NewChannelBinds()
	tunA, tunB := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	ka, kb := mustKey(t), mustKey(t)

	// The channel binds deliver bind 0's sends to "port" 1 and bind 1's to 2.
	epB := netip.MustParseAddrPort("127.0.0.1:1")
	epA := netip.MustParseAddrPort("127.0.0.1:2")
	// No keepalives: both ends initiating at the same instant makes each
	// answer the other's handshake with state it has just replaced, and the
	// retry that sorts it out waits five seconds. Here only A initiates.
	toB := peer(kb, "10.0.0.2/32")
	toB.Endpoint, toB.Keepalive = &epB, 0
	toA := peer(ka, "10.0.0.1/32")
	toA.Endpoint, toA.Keepalive = &epA, 0

	cfgA := Config{PrivateKey: ka, Peers: []Peer{toB}}
	a, err := UpOn(tunA.TUN(), cfgA, Options{Bind: binds[0]})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := UpOn(tunB.TUN(), Config{PrivateKey: kb, Peers: []Peer{toA}}, Options{Bind: binds[1]})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ping := func() {
		t.Helper()
		pkt := tuntest.Ping(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"))
		select {
		case tunA.Outbound <- pkt:
		case <-time.After(5 * time.Second):
			t.Fatal("device A is not reading its TUN")
		}
		select {
		case <-tunB.Inbound:
		case <-time.After(5 * time.Second):
			t.Fatal("packet never arrived at B")
		}
	}
	handshake := func() string {
		t.Helper()
		st, err := a.dev.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		_, rest, _ := strings.Cut(st, "public_key="+kb.Public().Hex())
		for _, line := range strings.Split(rest, "\n") {
			if strings.HasPrefix(line, "last_handshake_time_nsec=") {
				return line
			}
		}
		t.Fatalf("no handshake time for B in:\n%s", st)
		return ""
	}

	ping()
	before := handshake()
	if before == "last_handshake_time_nsec=0" {
		t.Fatal("no handshake happened")
	}

	// Somebody else joins the mesh.
	cfgA.Peers = append(cfgA.Peers, peer(mustKey(t), "10.0.0.3/32"))
	if err := a.SetConfig(cfgA); err != nil {
		t.Fatal(err)
	}
	if after := handshake(); after != before {
		t.Fatalf("B's session was replaced by an unrelated change: %s, then %s", before, after)
	}
	ping()

	// And leaves again.
	cfgA.Peers = cfgA.Peers[:1]
	if err := a.SetConfig(cfgA); err != nil {
		t.Fatal(err)
	}
	if after := handshake(); after != before {
		t.Fatalf("B's session was replaced when another peer left: %s, then %s", before, after)
	}
	ping()
}
