package control

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/clientip"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/relay"
)

func TestPollsAreCapped(t *testing.T) {
	p := newPolls(2)
	if !p.take() || !p.take() {
		t.Fatal("the first two polls were refused")
	}
	if p.take() {
		t.Error("a third poll was admitted past a cap of two")
	}
	p.done()
	if !p.take() {
		t.Error("a slot freed by a finished poll was not reused")
	}
}

func TestRegistersAreRateLimited(t *testing.T) {
	b := newBuckets(3, time.Second)
	now := time.Now()

	for i := range 3 {
		if !b.allow("10.0.0.1:1234", now) {
			t.Fatalf("attempt %d within the burst was refused", i+1)
		}
	}
	if b.allow("10.0.0.1:1234", now) {
		t.Error("a fourth attempt past the burst was allowed")
	}

	// Another address has its own budget.
	if !b.allow("10.0.0.2:1234", now) {
		t.Error("a different address was refused because of the first one")
	}

	// And the budget refills with time.
	if !b.allow("10.0.0.1:1234", now.Add(2*time.Second)) {
		t.Error("the bucket did not refill")
	}
}

// A new port is not a new client: the budget follows the address.
func TestANewPortDoesNotGetAFreshBudget(t *testing.T) {
	b := newBuckets(1, time.Minute)
	now := time.Now()

	if !b.allow("10.0.0.1:1111", now) {
		t.Fatal("the first attempt was refused")
	}
	if b.allow("10.0.0.1:2222", now) {
		t.Error("reconnecting from a new port got a fresh budget")
	}
}

// The table must not grow without bound for a server that is scanned.
func TestIdleAddressesAreForgotten(t *testing.T) {
	b := newBuckets(1, time.Second)
	start := time.Now()

	b.allow("10.0.0.1:1", start)
	b.allow("10.0.0.2:1", start)

	// A later arrival sweeps whatever has gone quiet.
	b.allow("10.0.0.3:1", start.Add(limiterIdleTTL+time.Minute))

	b.mu.Lock()
	n := len(b.at)
	b.mu.Unlock()
	if n != 1 {
		t.Errorf("the table holds %d addresses after a sweep, want 1", n)
	}
}

func TestHostOfDropsThePort(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1:4242":  "10.0.0.1",
		"[fd00::1]:4242": "fd00::1",
		"10.0.0.1":       "10.0.0.1",
		"":               "",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// register asks s to register, from remote, through a proxy that says it is
// forwarding for xff (none if empty), and reports whether the rate limit let
// it through. The body is not a real registration; anything but 503 means
// the limit was passed.
func register(h http.Handler, remote, xff string) bool {
	r := httptest.NewRequest(http.MethodPost, "/machine/register", strings.NewReader("{}"))
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code != http.StatusServiceUnavailable
}

// Behind a reverse proxy or a Cloudflare tunnel on the same machine, every
// request arrives from loopback. The limit used to count the proxy, so every
// node behind it shared ten registrations: a fleet restarting after an update
// locked most of itself out, and one noisy client could lock out the rest.
func TestNodesBehindAProxyEachHaveTheirOwnBudget(t *testing.T) {
	h := NewServer(newStore(t), log.New(io.Discard, "", 0)).Handler()

	for i := range 2 * registerBurst {
		if !register(h, "127.0.0.1:40000", fmt.Sprintf("198.51.100.%d", i+1)) {
			t.Fatalf("node %d behind the proxy was refused", i+1)
		}
	}

	// One client spending its own budget leaves the others theirs.
	for range registerBurst + 1 {
		register(h, "127.0.0.1:40000", "203.0.113.66")
	}
	if register(h, "127.0.0.1:40000", "203.0.113.66") {
		t.Error("a client behind the proxy went past its own budget")
	}
	if !register(h, "127.0.0.1:40000", "198.51.100.200") {
		t.Error("one client's spent budget refused another behind the same proxy")
	}
}

// The header is anybody's to write. From a peer that is not a trusted proxy
// it is ignored, or every request could name a new address and a new budget.
func TestAStrangersForwardedForBuysNothing(t *testing.T) {
	h := NewServer(newStore(t), log.New(io.Discard, "", 0)).Handler()

	refused := false
	for i := range registerBurst + 1 {
		if !register(h, "203.0.113.9:40000", fmt.Sprintf("198.51.100.%d", i+1)) {
			refused = true
		}
	}
	if !refused {
		t.Error("a direct client naming a new address each time was never limited")
	}
}

// The proxies to trust are the operator's to name, and the relay the server
// carries believes the same ones.
func TestTrustedProxiesCanBeNamed(t *testing.T) {
	s := NewServer(newStore(t), log.New(io.Discard, "", 0))
	s.SetTrustedProxies(clientip.Proxies{netip.MustParsePrefix("192.0.2.0/24")})
	h := s.Handler()

	for i := range registerBurst + 1 {
		if !register(h, "192.0.2.10:40000", fmt.Sprintf("198.51.100.%d", i+1)) {
			t.Fatalf("node %d behind a named proxy was refused", i+1)
		}
	}
	// Loopback is no longer trusted once the list is named without it.
	refused := false
	for i := range registerBurst + 1 {
		if !register(h, "127.0.0.1:40000", fmt.Sprintf("198.51.100.%d", i+1)) {
			refused = true
		}
	}
	if !refused {
		t.Error("loopback was still believed after the trusted list was replaced")
	}
}

// Addresses are cheap to come by — a scan, an IPv6 host walking its /64, a
// client behind a proxy that passes X-Forwarded-For through untouched — and
// every one used to be a row for ten minutes, however many arrived. A full
// table now puts new arrivals on one shared budget, and the addresses it
// already holds keep theirs.
func TestAFullTableSharesOneBudgetAndKeepsItsOwn(t *testing.T) {
	b := newBuckets(2, time.Minute)
	b.max = 2
	now := time.Now()

	b.allow("10.0.0.1", now)
	b.allow("10.0.0.2", now)

	// Past the limit, new arrivals spend one shared budget of two.
	if !b.allow("198.51.100.1", now) || !b.allow("198.51.100.2", now) {
		t.Fatal("arrivals past a full table were refused before the shared budget ran out")
	}
	if b.allow("198.51.100.3", now) {
		t.Error("a new address got a budget of its own past a full table")
	}
	b.mu.Lock()
	n := len(b.at)
	b.mu.Unlock()
	if n > b.max+1 {
		t.Errorf("the table grew to %d rows past a limit of %d", n, b.max)
	}

	// The address already held still has the token it did not spend.
	if !b.allow("10.0.0.1", now) {
		t.Error("a address the table already held lost its budget to the newcomers")
	}
}

// relayUpgrade asks the relay a control server carries for a connection, as
// a proxy forwarding for xff, and reports whether the relay took it.
func relayUpgrade(t *testing.T, base, xff string) bool {
	t.Helper()
	host := strings.TrimPrefix(base, "http://")
	c, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: %s\r\nConnection: Upgrade\r\nX-Forwarded-For: %s\r\n\r\n",
		relay.Path, host, relay.UpgradeProto, xff)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	return err == nil && resp.StatusCode == http.StatusSwitchingProtocols
}

// The relay a control server carries believes the proxies the server does,
// whichever of the two is set up first. Here no proxy is trusted, so a
// client on loopback naming a new address each time is still one client,
// and runs out of handshakes.
func TestTheCarriedRelayBelievesTheSameProxies(t *testing.T) {
	for _, relayFirst := range []bool{true, false} {
		s := NewServer(newStore(t), log.New(io.Discard, "", 0))
		priv, err := key.NewPrivate()
		if err != nil {
			t.Fatal(err)
		}
		rs := relay.NewServer(priv, log.New(io.Discard, "", 0))
		if relayFirst {
			s.SetRelay(rs)
			s.SetTrustedProxies(nil)
		} else {
			s.SetTrustedProxies(nil)
			s.SetRelay(rs)
		}
		ts := httptest.NewServer(s.Handler())

		refused := false
		for i := range 64 {
			if !relayUpgrade(t, ts.URL, fmt.Sprintf("198.51.100.%d", i+1)) {
				refused = true
				break
			}
		}
		ts.Close()
		rs.Close()
		if !refused {
			t.Errorf("relay set up first: %v — the relay believed a proxy the server does not", relayFirst)
		}
	}
}
