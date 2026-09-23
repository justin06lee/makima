package control

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/relay"
)

// meshWithRelay is a control server carrying its own relay, over real HTTP.
func meshWithRelay(t *testing.T) (*Store, string, key.Public) {
	t.Helper()

	store := newStore(t)
	relayKey, _ := key.NewPrivate()
	rs := relay.NewServer(relayKey, log.New(io.Discard, "", 0))

	srv := NewServer(store, log.New(io.Discard, "", 0))
	srv.SetRelay(rs, relayKey.Public())
	ts := httptest.NewServer(srv.Handler())

	t.Cleanup(func() {
		ts.Close()
		rs.Close()
	})
	return store, ts.URL, relayKey.Public()
}

// With nothing registered, every node is told to relay through the control
// plane itself — by path, so each can resolve it against however it reaches
// the server.
func TestNodesAreGivenTheBuiltinRelay(t *testing.T) {
	store, url, relayKey := meshWithRelay(t)
	auth, _ := store.MintAuthKey(true, time.Hour)

	a, _ := joinClient(t, store, url, "laptop", auth.Secret)
	joinClient(t, store, url, "tenet", auth.Secret)

	m, err := a.PollMap(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.HomeRelay.URL != relay.Path || m.HomeRelay.Key != relayKey {
		t.Errorf("home relay = %+v, want %s with the server's relay key", m.HomeRelay, relay.Path)
	}
	for _, p := range m.Peers {
		if p.RelayURL != relay.Path {
			t.Errorf("peer %s is advertised on relay %q, want %s", p.Name, p.RelayURL, relay.Path)
		}
	}
}

// A relay somebody registered on purpose — on a machine with better bandwidth
// than a home connection, say — wins over the built-in one.
func TestARegisteredRelayWinsOverTheBuiltinOne(t *testing.T) {
	store := newStore(t)
	builtin, _ := key.NewPrivate()
	store.SetBuiltinRelay(netmap.Relay{URL: relay.Path, Key: builtin.Public()})

	mk, _ := joinNamed(t, store, "laptop")

	vps, _ := key.NewPrivate()
	if err := store.AddRelay("vps.example:3478", vps.Public()); err != nil {
		t.Fatal(err)
	}
	m, err := store.NetMapFor(mk.Public())
	if err != nil {
		t.Fatal(err)
	}
	if m.HomeRelay.URL != "vps.example:3478" {
		t.Errorf("home relay = %q, want the registered one", m.HomeRelay.URL)
	}

	// And removing it falls back, rather than leaving the mesh with none.
	if err := store.RemoveRelay("vps.example:3478"); err != nil {
		t.Fatal(err)
	}
	m, _ = store.NetMapFor(mk.Public())
	if m.HomeRelay.URL != relay.Path {
		t.Errorf("after removal the home relay is %q, want the built-in one", m.HomeRelay.URL)
	}
}

// End to end: two nodes meet on the relay the control plane carries, reaching
// it at the same address they reach the control plane at.
func TestTwoNodesMeetOnTheControlPlanesRelay(t *testing.T) {
	_, url, relayKey := meshWithRelay(t)
	target := relay.Resolve(relay.Path, url)

	dial := func() (*relay.Client, key.Public) {
		nodeKey, _ := key.NewPrivate()
		c := relay.NewClient(target, relayKey, nodeKey)
		c.SetLogger(log.New(io.Discard, "", 0))
		ctx, cancel := context.WithCancel(context.Background())
		go c.Run(ctx)
		t.Cleanup(func() { cancel(); c.Close() })

		deadline := time.Now().Add(5 * time.Second)
		for !c.Connected() {
			if time.Now().After(deadline) {
				t.Fatalf("never connected to the relay at %s", target)
			}
			time.Sleep(5 * time.Millisecond)
		}
		return c, nodeKey.Public()
	}

	laptop, laptopKey := dial()
	desktop, desktopKey := dial()

	if err := laptop.Send(desktopKey, []byte("hello from the hotel")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := desktop.Recv(ctx)
	if err != nil {
		t.Fatalf("the packet never crossed: %v", err)
	}
	if p.Src != laptopKey || !bytes.Equal(p.Data, []byte("hello from the hotel")) {
		t.Errorf("got %q from %s", p.Data, p.Src)
	}
}
