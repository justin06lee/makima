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
	srv.SetRelay(rs)
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

// member registers a node and returns the node key it will present to the
// relay.
func member(t *testing.T, store *Store, name string) key.Private {
	t.Helper()
	auth, err := store.MintAuthKey(true, 0)
	if err != nil {
		t.Fatal(err)
	}
	machineKey, _ := key.NewPrivate()
	nodeKey, _ := key.NewPrivate()
	discoKey, _ := key.NewPrivate()
	if _, err := store.Register(machineKey.Public(), &RegisterRequest{
		Name: name, NodeKey: nodeKey.Public(), DiscoKey: discoKey.Public(), AuthKey: auth.Secret,
	}); err != nil {
		t.Fatal(err)
	}
	return nodeKey
}

// relayClient connects to the built-in relay as nodeKey.
func relayClient(t *testing.T, target string, relayKey key.Public, nodeKey key.Private) *relay.Client {
	t.Helper()
	c := relay.NewClient(target, relayKey, nodeKey)
	c.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	t.Cleanup(func() { cancel(); c.Close() })
	return c
}

func waitRelay(t *testing.T, c *relay.Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !c.Connected() {
		if time.Now().After(deadline) {
			t.Fatalf("never connected to the relay at %s", c.URL())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// End to end: two nodes meet on the relay the control plane carries, reaching
// it at the same address they reach the control plane at.
func TestTwoNodesMeetOnTheControlPlanesRelay(t *testing.T) {
	store, url, relayKey := meshWithRelay(t)
	target := relay.Resolve(relay.Path, url)

	laptopKey := member(t, store, "laptop")
	desktopKey := member(t, store, "desktop")
	laptop := relayClient(t, target, relayKey, laptopKey)
	desktop := relayClient(t, target, relayKey, desktopKey)
	waitRelay(t, laptop)
	waitRelay(t, desktop)

	if err := laptop.Send(desktopKey.Public(), []byte("hello from the hotel")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := desktop.Recv(ctx)
	if err != nil {
		t.Fatalf("the packet never crossed: %v", err)
	}
	if p.Src != laptopKey.Public() || !bytes.Equal(p.Data, []byte("hello from the hotel")) {
		t.Errorf("got %q from %s", p.Data, p.Src)
	}
}

// The relay sits on a home connection's open port. It carries this network's
// nodes and nobody else's — not a stranger with a key of their own, and not a
// node an operator has expired.
func TestTheBuiltinRelayServesOnlyMembers(t *testing.T) {
	store, url, relayKey := meshWithRelay(t)
	target := relay.Resolve(relay.Path, url)

	stranger, _ := key.NewPrivate()
	c := relayClient(t, target, relayKey, stranger)
	time.Sleep(300 * time.Millisecond)
	if c.Connected() {
		t.Error("a key that is no node of this network was let onto the relay")
	}

	laptop := member(t, store, "laptop")
	if err := store.ExpireNode("laptop"); err != nil {
		t.Fatal(err)
	}
	c = relayClient(t, target, relayKey, laptop)
	time.Sleep(300 * time.Millisecond)
	if c.Connected() {
		t.Error("an expired node was let onto the relay")
	}

	desktop := member(t, store, "desktop")
	waitRelay(t, relayClient(t, target, relayKey, desktop))
}
