package control

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/bypass"
	"github.com/justin06lee/makima/internal/key"
)

// fakeOnion is a binder whose "tor" reaches target directly, counting how
// often it is used: an onion address in a test, without tor.
func fakeOnion(target string) (*bypass.Binder, *atomic.Int32) {
	var dials atomic.Int32
	b := &bypass.Binder{}
	b.SetOnion(func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	})
	return b, &dials
}

// hostPort is an http URL's host:port.
func hostPort(u string) string { return u[len("http://"):] }

// waitFor polls cond until it holds or a few seconds pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("gave up waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ownOnly makes the given addresses this machine's for the test.
func ownOnly(t *testing.T, own ...string) {
	t.Helper()
	was := ownAddress
	ownAddress = func(a netip.Addr) bool {
		return a.IsLoopback() || slices.Contains(own, a.String())
	}
	t.Cleanup(func() { ownAddress = was })
}

func TestRankPutsDirectAddressesBeforeTheOnion(t *testing.T) {
	ownOnly(t)
	onion := OnionURL(onionA)
	cases := []struct {
		name   string
		joined string
		alts   []string
		want   []string
	}{
		{
			// The server names where it is now; the address this node
			// joined through has gone stale behind it, and is kept only as
			// a last direct try.
			name:   "stale joined",
			joined: "http://192.168.1.249:8080",
			alts:   []string{"http://192.168.1.213:8080", "https://makima.example.dev", onion},
			want:   []string{"http://192.168.1.213:8080", "http://192.168.1.249:8080", "https://makima.example.dev", onion},
		},
		{
			// A server from before it named its own addresses: the joined
			// one stays ahead of the names, as it always was.
			name:   "older server",
			joined: "http://192.168.1.20:8080",
			alts:   []string{"https://makima.example.dev", onion},
			want:   []string{"http://192.168.1.20:8080", "https://makima.example.dev", onion},
		},
		{
			// Joined through an invite's onion address: every direct address
			// comes first all the same.
			name:   "joined by onion",
			joined: OnionURL(onionB),
			alts:   []string{"http://10.0.0.5:8080", onion},
			want:   []string{"http://10.0.0.5:8080", onion, OnionURL(onionB)},
		},
	}
	for _, tc := range cases {
		if got := rank(tc.joined, tc.alts, ""); !slices.Equal(got, tc.want) {
			t.Errorf("%s: rank = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// On the machine holding the network, any address of its own the server
// names is reached over loopback, ahead of everything else.
func TestRankReachesAServerOnThisMachineOverLoopback(t *testing.T) {
	ownOnly(t, "192.168.1.213")
	got := rank("http://192.168.1.249:8080", []string{"http://192.168.1.213:8080", OnionURL(onionA)}, "")
	want := []string{"http://127.0.0.1:8080", "http://192.168.1.213:8080", "http://192.168.1.249:8080", OnionURL(onionA)}
	if !slices.Equal(got, want) {
		t.Errorf("rank = %v, want %v", got, want)
	}
}

// The case that kept the Mac and the Jetson dropping: the address a node
// joined through went stale when the server's DHCP lease moved, so every
// check-in and the relay rode tor. Once the server names where it is now,
// the node goes there and leaves tor alone.
func TestNodeWithAStaleAddressFindsTheServerAgain(t *testing.T) {
	ownOnly(t)
	store := newStore(t)
	if err := store.SetOnion(onionA); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(store, log.New(io.Discard, "", 0)).Handler()
	direct := httptest.NewServer(handler)
	t.Cleanup(direct.Close)
	live := direct.URL

	// Tor, in this test, is a listener of its own in front of the same
	// server, which counts the polls held open there and given up on.
	var abandoned atomic.Int32
	viaTor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		if r.URL.Path == "/machine/map" && r.Context().Err() != nil {
			abandoned.Add(1)
		}
	}))
	t.Cleanup(viaTor.Close)

	auth, _ := store.MintAuthKey(true, time.Hour)
	joined, _ := joinClient(t, store, live, "laptop", auth.Secret)
	b, onionDials := fakeOnion(hostPort(viaTor.URL))

	stale := deadURL(t)
	c := NewClient(stale, store.ServerKey().Public(), joined.machineKey)
	c.SetBinder(b)
	c.SetAlternates([]string{OnionURL(onionA)})

	m, err := c.PollMap(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.BaseURL(); got != OnionURL(onionA) {
		t.Fatalf("with only its stale address and the onion, the node is on %s", got)
	}

	// The server finds its address; the node hears it over tor, as makimad
	// hands every netmap's addresses to its client.
	store.SetLocalURLs([]string{live})
	if m, err = c.PollMap(context.Background(), m.Version, nil); err != nil {
		t.Fatal(err)
	}
	c.SetAlternates(m.ControlURLs)

	// The next poll is held open — nothing new to say — and it does not sit
	// out its minute on tor: it is given up there, and held open at the
	// direct address instead, where the next change reaches it.
	go func() {
		for deadline := time.Now().Add(5 * time.Second); abandoned.Load() == 0 && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		store.AddControlURL("https://makima.example.dev")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.PollMap(ctx, m.Version, nil); err != nil {
		t.Fatalf("the held poll: %v", err)
	}
	if got := c.BaseURL(); got != live {
		t.Fatalf("after the poll the node is on %s", got)
	}

	before := onionDials.Load()
	for range 3 {
		if _, err := c.PollMap(context.Background(), 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	if onionDials.Load() != before {
		t.Errorf("the node went through tor %d more time(s) with a direct address answering", onionDials.Load()-before)
	}
}

// The machine holding the network reaches its own server over loopback and
// never through tor — not even while the server restarts under it, when tor
// would only lead back to the same stopped server, the slow way.
func TestHolderNeverGoesThroughTor(t *testing.T) {
	store := newStore(t)
	if err := store.SetOnion(onionA); err != nil {
		t.Fatal(err)
	}
	auth, _ := store.MintAuthKey(true, time.Hour)
	handler := NewServer(store, log.New(io.Discard, "", 0)).Handler()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	live := "http://" + ln.Addr().String()
	joined, _ := joinClient(t, store, live, "midna", auth.Secret)

	// What the holder's node has: its stale LAN address, and what the server
	// names — its LAN address now, which this machine holds, and the onion.
	ownOnly(t, "192.0.2.10")
	setProbeTimeout(t, 300*time.Millisecond)
	b, onionDials := fakeOnion(ln.Addr().String())
	lan := "http://" + netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(addr.Port)).String()

	c := NewClient("http://192.0.2.99:8080", store.ServerKey().Public(), joined.machineKey)
	c.SetBinder(b)
	c.SetAlternates([]string{lan, OnionURL(onionA)})

	if _, err := c.PollMap(context.Background(), 0, nil); err != nil {
		t.Fatal(err)
	}
	if got := c.BaseURL(); got != live {
		t.Fatalf("the holder reaches its server at %s, want %s", got, live)
	}

	// The server stops: the holder waits for it rather than going to tor.
	srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.PollMap(ctx, 0, nil); err == nil {
		t.Fatal("a poll succeeded with the server stopped")
	}
	if n := onionDials.Load(); n != 0 {
		t.Fatalf("the holder went through tor %d time(s) to reach a server on its own machine", n)
	}

	// And it comes back, at the same place.
	ln2, err := net.Listen("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("could not listen again on %s: %v", ln.Addr(), err)
	}
	srv2 := &http.Server{Handler: handler}
	go srv2.Serve(ln2)
	t.Cleanup(func() { srv2.Close() })
	if _, err := c.PollMap(context.Background(), 0, nil); err != nil {
		t.Fatal(err)
	}
	if got := c.BaseURL(); got != live {
		t.Errorf("after the restart the holder is on %s", got)
	}
	if n := onionDials.Load(); n != 0 {
		t.Errorf("the holder went through tor %d time(s)", n)
	}
}

// A node that has never reached its server over loopback is not a holder,
// whatever addresses it shares with one, and still falls back to the onion.
func TestOnlyAVerifiedLocalServerKeepsANodeOffTor(t *testing.T) {
	ownOnly(t)
	store, live := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)
	joined, _ := joinClient(t, store, live, "laptop", auth.Secret)
	b, onionDials := fakeOnion(hostPort(live))

	c := NewClient(deadURL(t), store.ServerKey().Public(), joined.machineKey)
	c.SetBinder(b)
	c.SetAlternates([]string{OnionURL(onionA)})
	if _, err := c.PollMap(context.Background(), 0, nil); err != nil {
		t.Fatalf("a dead loopback address kept the node off its onion fallback: %v", err)
	}
	if onionDials.Load() == 0 {
		t.Error("the onion address was never tried")
	}
}

// Asking a stranger's server for the key is not mistaken for finding ours.
func TestProbeWantsOurServersKey(t *testing.T) {
	store, live := testMesh(t)
	other, _ := key.NewPrivate()
	machine, _ := key.NewPrivate()
	c := NewClient(live, other.Public(), machine)
	if err := c.knows(context.Background(), live); err == nil {
		t.Error("a server with another key passed for ours")
	}
	c = NewClient(live, store.ServerKey().Public(), machine)
	if err := c.knows(context.Background(), live); err != nil {
		t.Errorf("our own server: %v", err)
	}
	if err := c.knows(context.Background(), deadURL(t)); err == nil || errors.Is(err, context.Canceled) {
		t.Errorf("a dead address: %v", err)
	}
}

func setProbeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	was := probeTimeout
	probeTimeout = d
	t.Cleanup(func() { probeTimeout = was })
}
