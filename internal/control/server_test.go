package control

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// testMesh spins up a real HTTP control server backed by a temp store.
func testMesh(t *testing.T) (*Store, string) {
	t.Helper()
	store := newStore(t)
	srv := httptest.NewServer(NewServer(store, log.New(io.Discard, "", 0)).Handler())
	t.Cleanup(srv.Close)
	return store, srv.URL
}

// joinClient registers a fresh node and returns a client speaking as it.
func joinClient(t *testing.T, store *Store, url, name, authKey string) (*Client, *RegisterResponse) {
	t.Helper()

	machineKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	discoKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	c := NewClient(url, store.ServerKey().Public(), machineKey)
	resp, err := c.Register(context.Background(), &RegisterRequest{
		Name: name, NodeKey: nodeKey.Public(), DiscoKey: discoKey.Public(), AuthKey: authKey,
	})
	if err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	return c, resp
}

func TestFetchServerKeyMatches(t *testing.T) {
	store, url := testMesh(t)

	got, err := FetchServerKey(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	if got != store.ServerKey().Public() {
		t.Error("the published key is not the server's actual key")
	}
}

func TestRegisterAndPollOverHTTP(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)

	ca, ra := joinClient(t, store, url, "alpha", auth.Secret)
	if ra.Address.Addr().String() != "100.64.0.1" {
		t.Errorf("alpha got %s, want 100.64.0.1", ra.Address.Addr())
	}

	_, rb := joinClient(t, store, url, "beta", auth.Secret)
	if rb.Address.Addr().String() != "100.64.0.2" {
		t.Errorf("beta got %s, want 100.64.0.2", rb.Address.Addr())
	}

	m, err := ca.PollMap(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Self.Name != "alpha" {
		t.Errorf("Self is %q, want alpha", m.Self.Name)
	}
	if len(m.Peers) != 1 || m.Peers[0].Name != "beta" {
		t.Fatalf("alpha's peers are %+v, want just beta", m.Peers)
	}
	if len(m.Peers[0].Addresses) == 0 || m.Peers[0].Addresses[0] != rb.Address {
		t.Error("beta's address did not survive the round trip")
	}
}

// The point of the long poll: a node waiting on the current version is woken
// by a change rather than discovering it on a timer.
func TestLongPollWakesOnNewPeer(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)

	ca, _ := joinClient(t, store, url, "alpha", auth.Secret)

	current, err := ca.PollMap(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type result struct {
		m   *MapResponse
		err error
	}
	done := make(chan result, 1)
	go func() {
		m, err := ca.PollMap(ctx, current.Version, nil)
		done <- result{m, err}
	}()

	// Give the poll a moment to actually be parked on the server before the
	// change lands, so the test exercises the wake path rather than the
	// already-newer fast path.
	waitForPollers(t, store, current.Version)

	joinClient(t, store, url, "gamma", auth.Secret)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("long poll failed: %v", r.err)
		}
		if r.m.Version <= current.Version {
			t.Errorf("woke with version %d, not newer than %d", r.m.Version, current.Version)
		}
		var names []string
		for _, p := range r.m.Peers {
			names = append(names, p.Name)
		}
		if len(names) != 1 || names[0] != "gamma" {
			t.Errorf("peers after wake: %v, want [gamma]", names)
		}
	case <-ctx.Done():
		t.Fatal("long poll never woke after a new node joined")
	}
}

// waitForPollers blocks until the store's version is stable and at least one
// poll has had a chance to park. There is no hook for "a request is waiting",
// so this settles for confirming the version the poller asked for is current.
func waitForPollers(t *testing.T, store *Store, version uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if store.Version() == version {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("store version never settled at %d (now %d)", version, store.Version())
}

// A node the server has never seen must be refused, not handed someone
// else's netmap.
func TestUnknownMachineKeyRefused(t *testing.T) {
	store, url := testMesh(t)

	stranger, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(url, store.ServerKey().Public(), stranger)

	if _, err := c.PollMap(context.Background(), 0, nil); err == nil {
		t.Error("an unregistered machine key received a netmap")
	}
}

// Sealing to the wrong server key must fail at the transport, since
// decryption is the only authentication step there is.
func TestWrongServerKeyRejected(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)
	joinClient(t, store, url, "alpha", auth.Secret)

	impostor, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	machineKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	c := NewClient(url, impostor.Public(), machineKey)
	if _, err := c.Register(context.Background(), &RegisterRequest{
		Name: "bad", NodeKey: machineKey.Public(), DiscoKey: machineKey.Public(), AuthKey: auth.Secret,
	}); err == nil {
		t.Error("a request sealed to the wrong server key was accepted")
	}
}

// Forgetting a node must propagate: every other node drops it on the next map.
func TestForgetPropagates(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)

	ca, _ := joinClient(t, store, url, "alpha", auth.Secret)
	joinClient(t, store, url, "doomed", auth.Secret)

	before, err := ca.PollMap(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(before.Peers))
	}

	if err := store.Forget("doomed"); err != nil {
		t.Fatal(err)
	}

	after, err := ca.PollMap(context.Background(), before.Version, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Peers) != 0 {
		t.Errorf("forgotten node still present: %+v", after.Peers)
	}
}
