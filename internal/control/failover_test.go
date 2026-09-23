package control

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// deadURL is an address nothing is listening on: a port that was just freed.
func deadURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}

// The laptop that left the house: the address it joined through no longer
// answers, the public one does, and it carries on without being told twice.
func TestClientFallsBackToAnotherAddress(t *testing.T) {
	store, live := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)
	joined, _ := joinClient(t, store, live, "laptop", auth.Secret)

	dead := deadURL(t)
	c := NewClient(dead, store.ServerKey().Public(), joined.machineKey)
	c.SetAlternates([]string{live})

	if _, err := c.PollMap(context.Background(), 0, nil); err != nil {
		t.Fatalf("poll with the first address dead: %v", err)
	}
	if got := c.BaseURL(); got != live {
		t.Errorf("in use: %s, want the address that answered (%s)", got, live)
	}

	// And it stays there, rather than knocking on the dead one every poll.
	if _, err := c.PollMap(context.Background(), 0, nil); err != nil {
		t.Fatal(err)
	}
	if got := c.BaseURL(); got != live {
		t.Errorf("drifted back to %s", got)
	}
}

// Away from home the LAN address can belong to some other machine — a hotel
// router with a web page on the same port. Only a reply that opens under the
// server's key counts as the control plane answering.
func TestSomebodyElsesServerIsNotTheControlPlane(t *testing.T) {
	store, live := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)
	joined, _ := joinClient(t, store, live, "laptop", auth.Secret)

	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":2,"machine_key":"","nonce":"","payload":""}`))
	}))
	t.Cleanup(impostor.Close)

	c := NewClient(impostor.URL, store.ServerKey().Public(), joined.machineKey)
	c.SetAlternates([]string{live})

	if _, err := c.PollMap(context.Background(), 0, nil); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if got := c.BaseURL(); got != live {
		t.Errorf("settled on %s, want the real control plane at %s", got, live)
	}
}

// With every address down, the error names each one, so somebody reading the
// log can see which address failed how.
func TestEveryAddressFailingIsReported(t *testing.T) {
	serverKey, _ := key.NewPrivate()
	machineKey, _ := key.NewPrivate()
	a, b := deadURL(t), deadURL(t)

	c := NewClient(a, serverKey.Public(), machineKey)
	c.SetAlternates([]string{b})

	_, err := c.PollMap(context.Background(), 0, nil)
	if err == nil {
		t.Fatal("poll succeeded with no server anywhere")
	}
	for _, u := range []string{a, b} {
		if !strings.Contains(err.Error(), u) {
			t.Errorf("error does not mention %s: %v", u, err)
		}
	}
}

// Learning about new addresses must not move a client off one that works,
// and the address it joined through always stays first.
func TestSetAlternatesKeepsTheAddressInUse(t *testing.T) {
	k, _ := key.NewPrivate()
	c := NewClient("http://192.168.1.20:8080", k.Public(), k)
	c.SetAlternates([]string{"http://tenet.duckdns.org:8080"})
	c.cur = 1

	c.SetAlternates([]string{"https://makima.example.dev", "http://tenet.duckdns.org:8080/"})
	if got := c.BaseURL(); got != "http://tenet.duckdns.org:8080" {
		t.Errorf("in use: %s, want it unchanged", got)
	}
	want := []string{"http://192.168.1.20:8080", "https://makima.example.dev", "http://tenet.duckdns.org:8080"}
	if !slices.Equal(c.urls, want) {
		t.Errorf("urls = %v, want %v", c.urls, want)
	}

	// Dropping the one in use falls back to the first, rather than to an
	// index that now points somewhere else.
	c.SetAlternates(nil)
	if got := c.BaseURL(); got != "http://192.168.1.20:8080" {
		t.Errorf("after its address was dropped the client uses %s", got)
	}
}

// Every node is told the server's other addresses, and learns about a new one
// without waiting for anything else to change.
func TestControlURLsReachEveryNode(t *testing.T) {
	store := newStore(t)
	mk, _ := joinNamed(t, store, "laptop")
	before := store.Version()

	if err := store.AddControlURL("tenet.duckdns.org:8080"); err != nil {
		t.Fatal(err)
	}
	if store.Version() == before {
		t.Error("adding an address did not wake the pollers")
	}

	m, err := store.NetMapFor(mk.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.ControlURLs, []string{"http://tenet.duckdns.org:8080"}) {
		t.Errorf("control URLs = %v", m.ControlURLs)
	}

	if err := store.RemoveControlURL("http://tenet.duckdns.org:8080/"); err != nil {
		t.Fatal(err)
	}
	m, _ = store.NetMapFor(mk.Public())
	if len(m.ControlURLs) != 0 {
		t.Errorf("still told about %v after removal", m.ControlURLs)
	}
}

func TestNormalizeControlURL(t *testing.T) {
	good := map[string]string{
		"tenet.duckdns.org:8080":         "http://tenet.duckdns.org:8080",
		"http://tenet.duckdns.org:8080/": "http://tenet.duckdns.org:8080",
		"https://makima.example.dev":     "https://makima.example.dev",
		" 107.214.144.123:8080 ":         "http://107.214.144.123:8080",
	}
	for in, want := range good {
		got, err := NormalizeControlURL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeControlURL(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://tenet", "http://"} {
		if _, err := NormalizeControlURL(bad); err == nil {
			t.Errorf("NormalizeControlURL(%q) was accepted", bad)
		}
	}
}
