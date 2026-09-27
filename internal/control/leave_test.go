package control

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// A machine that takes itself off the network is gone from every other
// machine's netmap, and is itself a stranger from then on. This is what keeps
// a reset machine from lingering on the others as an offline entry.
func TestALeavingMachineDropsOutOfEveryNetmap(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)

	desktop, _ := joinClient(t, store, url, "desktop", auth.Secret)
	laptop, _ := joinClient(t, store, url, "laptop", auth.Secret)

	before, err := desktop.PollMap(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Peers) != 1 {
		t.Fatalf("desktop sees %d peers before, want 1", len(before.Peers))
	}

	name, err := laptop.Leave(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if name != "laptop" {
		t.Errorf("Leave named %q, want laptop", name)
	}

	after, err := desktop.PollMap(context.Background(), before.Version, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Peers) != 0 {
		t.Errorf("the laptop left and is still in the desktop's netmap: %+v", after.Peers)
	}
	if _, err := laptop.PollMap(context.Background(), 0, nil); err == nil {
		t.Error("the laptop left and was still handed a netmap")
	}
}

// Leaving is idempotent: asking again, or asking as a machine the network
// never had, is already done — and takes nobody else with it.
func TestLeavingWhatYouAreNotOnIsAlreadyDone(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)
	joinClient(t, store, url, "desktop", auth.Secret)
	laptop, _ := joinClient(t, store, url, "laptop", auth.Secret)

	if _, err := laptop.Leave(context.Background()); err != nil {
		t.Fatal(err)
	}
	name, err := laptop.Leave(context.Background())
	if err != nil || name != "" {
		t.Errorf("leaving twice = %q, %v; want \"\", nil", name, err)
	}

	stranger, _ := key.NewPrivate()
	name, err = NewClient(url, store.ServerKey().Public(), stranger).Leave(context.Background())
	if err != nil || name != "" {
		t.Errorf("a stranger leaving = %q, %v; want \"\", nil", name, err)
	}
	if n := len(store.Nodes()); n != 1 {
		t.Errorf("%d nodes left, want only the desktop", n)
	}
}

// The request carries no name to remove: the only machine it can take off is
// the one whose key sealed it, and a request sealed to some other server's key
// does not open here at all.
func TestOnlyTheMachineItselfCanLeave(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)
	joinClient(t, store, url, "laptop", auth.Secret)

	impostor, _ := key.NewPrivate()
	machine, _ := key.NewPrivate()
	if _, err := NewClient(url, impostor.Public(), machine).Leave(context.Background()); err == nil {
		t.Error("a leave sealed to the wrong server key was answered")
	}
	if n := len(store.Nodes()); n != 1 {
		t.Errorf("%d nodes, want the laptop still there", n)
	}
}

// Being expired by an operator is no reason to stay listed.
func TestAnExpiredMachineMayStillLeave(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)
	laptop, _ := joinClient(t, store, url, "laptop", auth.Secret)

	if err := store.ExpireNode("laptop"); err != nil {
		t.Fatal(err)
	}
	if name, err := laptop.Leave(context.Background()); err != nil || name != "laptop" {
		t.Fatalf("Leave = %q, %v", name, err)
	}
	if n := len(store.Nodes()); n != 0 {
		t.Errorf("%d nodes left, want none", n)
	}
}

// A control plane from before this request answers 404 at every address;
// the caller is told that, rather than that the server could not be reached,
// so it can say what to do instead.
func TestAnOldControlPlaneSaysMachinesCannotLeave(t *testing.T) {
	store := newStore(t)
	h := NewServer(store, log.New(io.Discard, "", 0)).Handler()
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/machine/leave" {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(old.Close)
	auth, _ := store.MintAuthKey(true, time.Hour)
	c, _ := joinClient(t, store, old.URL, "laptop", auth.Secret)

	if _, err := c.Leave(context.Background()); !errors.Is(err, ErrNoLeave) {
		t.Fatalf("err = %v, want ErrNoLeave", err)
	}
}
