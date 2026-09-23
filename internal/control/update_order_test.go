package control

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

// One machine asks; every machine hears it on its next netmap, reports how it
// is going, and the asker watches the others arrive.
func TestAnUpdateOrderReachesEveryNodeAndProgressComesBack(t *testing.T) {
	store, url := testMesh(t)
	store.SetServerVersion("v0.3.0")
	auth, _ := store.MintAuthKey(true, time.Hour)
	laptop, _ := joinClient(t, store, url, "laptop", auth.Secret)
	desktop, _ := joinClient(t, store, url, "desktop", auth.Secret)
	ctx := context.Background()

	before, err := desktop.Poll(ctx, &MapRequest{Running: "v0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if before.Update != nil {
		t.Fatalf("an order before anybody asked: %+v", before.Update)
	}
	if before.ServerVersion != "v0.3.0" {
		t.Errorf("server version = %q", before.ServerVersion)
	}

	o, err := laptop.RequestUpdate(ctx, "0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if o.Tag != "v0.3.0" || o.By != "laptop" || o.ID != 1 {
		t.Fatalf("order = %+v", o)
	}

	// The desktop's parked poll wakes with the order in it.
	m, err := desktop.Poll(ctx, &MapRequest{Version: before.Version, Running: "v0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Update == nil || m.Update.Tag != "v0.3.0" || m.Update.ID != 1 {
		t.Fatalf("desktop's netmap carries %+v", m.Update)
	}

	// The desktop says how it is going; the laptop sees it.
	installing := &netmap.UpdateStatus{Tag: "v0.3.0", State: netmap.UpdateInstalling}
	if _, err := desktop.Poll(ctx, &MapRequest{Version: m.Version, Running: "v0.2.0", Update: installing}); err != nil {
		t.Fatal(err)
	}
	seen := peerNamed(t, laptop, "desktop")
	if seen.Version != "v0.2.0" || seen.Update == nil || seen.Update.State != netmap.UpdateInstalling {
		t.Fatalf("laptop sees desktop as %q, %+v", seen.Version, seen.Update)
	}

	// And then arrive.
	if _, err := desktop.Poll(ctx, &MapRequest{Running: "v0.3.0"}); err != nil {
		t.Fatal(err)
	}
	seen = peerNamed(t, laptop, "desktop")
	if seen.Version != "v0.3.0" || seen.Update != nil {
		t.Fatalf("laptop sees desktop as %q, %+v", seen.Version, seen.Update)
	}

	// Asking again is a new order, so a machine that failed the last one
	// tries again.
	again, err := laptop.RequestUpdate(ctx, "v0.3.0")
	if err != nil || again.ID != 2 {
		t.Fatalf("second order = %+v, %v", again, err)
	}
}

func peerNamed(t *testing.T, c *Client, name string) netmap.Node {
	t.Helper()
	m, err := c.Poll(context.Background(), &MapRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range m.Peers {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no peer %s", name)
	return netmap.Node{}
}

// An order only ever names a release. Anything else is refused before it
// reaches a single node.
func TestAnUpdateOrderMustNameARelease(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)
	c, _ := joinClient(t, store, url, "laptop", auth.Secret)
	for _, tag := range []string{"", "latest", "master", "v1.2", "../../etc", "v1.2.3 && rm"} {
		if _, err := c.RequestUpdate(context.Background(), tag); err == nil {
			t.Errorf("%q was accepted", tag)
		}
	}
	if _, ok := store.UpdateOrdered(); ok {
		t.Error("a refused request left an order behind")
	}
}

// A stranger — anyone without a machine key the network knows — cannot give
// the order.
func TestAStrangerCannotOrderAnUpdate(t *testing.T) {
	store, url := testMesh(t)
	stranger, _ := key.NewPrivate()
	c := NewClient(url, store.ServerKey().Public(), stranger)
	if _, err := c.RequestUpdate(context.Background(), "v0.3.0"); err == nil {
		t.Fatal("a machine outside the network gave an order")
	}
	if _, ok := store.UpdateOrdered(); ok {
		t.Error("an order was recorded")
	}
}

// The order outlives the server, so a machine that was off when it was given
// still gets it.
func TestAnUpdateOrderSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestUpdate("admin", "v0.3.0"); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	o, ok := s2.UpdateOrdered()
	if !ok || o.Tag != "v0.3.0" || o.By != "admin" {
		t.Fatalf("after a restart the order is %+v, %v", o, ok)
	}
}

// A control plane from before remote updates answers the request with a 404,
// which the client turns into something a person can act on.
func TestAnOldControlPlaneSaysItCannotPassAnUpdateOn(t *testing.T) {
	store := newStore(t)
	h := NewServer(store, log.New(io.Discard, "", 0)).Handler()
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/machine/update" {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(old.Close)
	auth, _ := store.MintAuthKey(true, time.Hour)
	c, _ := joinClient(t, store, old.URL, "laptop", auth.Secret)

	if _, err := c.RequestUpdate(context.Background(), "v0.3.0"); !errors.Is(err, ErrNoRemoteUpdates) {
		t.Fatalf("err = %v", err)
	}
}
