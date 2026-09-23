package control

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/ddns"
)

// The name has to reach every node as a way back in, not only DuckDNS.
func TestADDNSNameIsHandedToEveryNode(t *testing.T) {
	store := newStore(t)
	mk, _ := joinNamed(t, store, "laptop")

	u, err := store.SetDDNS(DDNS{Name: "tenet.duckdns.org", Token: "tok", Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	if u != "http://tenet.duckdns.org:8080" {
		t.Errorf("url = %q", u)
	}

	m, err := store.NetMapFor(mk.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.ControlURLs, []string{"http://tenet.duckdns.org:8080"}) {
		t.Errorf("nodes are told %v", m.ControlURLs)
	}
}

// Changing the name replaces the old address rather than leaving nodes to try
// one that no longer leads anywhere; turning it off removes it.
func TestRenamingAndClearingKeepTheAddressListHonest(t *testing.T) {
	store := newStore(t)
	if err := store.AddControlURL("https://makima.example.dev"); err != nil {
		t.Fatal(err)
	}
	store.SetDDNS(DDNS{Name: "tenet", Token: "tok", Port: 8080})
	store.SetDDNS(DDNS{Name: "home", Token: "tok", Port: 8080})

	want := []string{"https://makima.example.dev", "http://home.duckdns.org:8080"}
	if got := store.ControlURLs(); !slices.Equal(got, want) {
		t.Errorf("after renaming: %v, want %v", got, want)
	}

	if err := store.ClearDDNS(); err != nil {
		t.Fatal(err)
	}
	if got := store.ControlURLs(); !slices.Equal(got, want[:1]) {
		t.Errorf("after clearing: %v, want only the address added by hand", got)
	}
	if store.DDNSConfig() != nil {
		t.Error("the name survived being turned off")
	}
}

// The token is a credential for somebody's DuckDNS account. It is stored, and
// it goes to DuckDNS, and it goes nowhere else — not into the status an admin
// command prints, and not into the netmap every node receives.
func TestTheTokenStaysOnTheServer(t *testing.T) {
	store := newStore(t)
	mk, _ := joinNamed(t, store, "laptop")
	store.SetDDNS(DDNS{Name: "tenet", Token: "very-secret-token", Port: 8080})

	st, _ := json.Marshal(store.DDNSState())
	m, _ := store.NetMapFor(mk.Public())
	nm, _ := json.Marshal(m)
	for what, b := range map[string][]byte{"status": st, "netmap": nm} {
		if strings.Contains(string(b), "very-secret-token") {
			t.Errorf("the token is in the %s", what)
		}
	}
}

// End to end against a stand-in DuckDNS: setting a name refreshes it at once,
// and the status reports where it points.
func TestRunDDNSKeepsTheNameCurrent(t *testing.T) {
	var calls atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("token") != "tok" {
			io.WriteString(w, "KO")
			return
		}
		io.WriteString(w, "OK\n107.214.144.123\n\nUPDATED")
	}))
	t.Cleanup(fake.Close)
	old := ddns.Endpoint
	ddns.Endpoint = fake.URL + "/update"
	t.Cleanup(func() { ddns.Endpoint = old })

	store := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunDDNS(ctx, store, log.New(io.Discard, "", 0))

	if _, err := store.SetDDNS(DDNS{Name: "tenet", Token: "tok", Port: 8080}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for store.DDNSState().IP == "" {
		if time.Now().After(deadline) {
			t.Fatalf("never refreshed; %d call(s) made, status %+v", calls.Load(), store.DDNSState())
		}
		time.Sleep(10 * time.Millisecond)
	}
	st := store.DDNSState()
	if st.IP != "107.214.144.123" || st.Name != "tenet.duckdns.org" || st.Error != "" {
		t.Errorf("status = %+v", st)
	}

	// A wrong token is reported in the status, where `ddns` will show it.
	store.SetDDNS(DDNS{Name: "tenet", Token: "wrong", Port: 8080})
	for store.DDNSState().Error == "" {
		if time.Now().After(deadline) {
			t.Fatal("a refused update was never reported")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Set through the admin socket with no port, the name is assumed forwarded to
// the port the server listens on — the common case, and the one nobody should
// have to type.
func TestTheAdminRouteUsesTheServersOwnPort(t *testing.T) {
	store := newStore(t)
	srv := NewServer(store, log.New(io.Discard, "", 0))
	srv.SetListenPort(8443)
	ts := httptest.NewServer(srv.AdminHandler())
	t.Cleanup(ts.Close)

	body := strings.NewReader(`{"name":"tenet","token":"tok"}`)
	resp, err := http.Post(ts.URL+"/admin/ddns", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got DDNSSetResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.URL != "http://tenet.duckdns.org:8443" {
		t.Errorf("url = %q, want the server's own port", got.URL)
	}
}
