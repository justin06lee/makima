package relay

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// webRelay starts a relay carried by an ordinary web server at Path, beside a
// page of its own, and returns the server's base URL.
func webRelayServer(t *testing.T) (string, key.Public) {
	t.Helper()
	return webRelayServerWith(t, func(*Server) {})
}

// webRelayServerWith is webRelayServer with the relay configured first.
func webRelayServerWith(t *testing.T, configure func(*Server)) (string, key.Public) {
	t.Helper()

	priv, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(priv, log.New(io.Discard, "", 0))
	configure(srv)

	mux := http.NewServeMux()
	mux.Handle("GET "+Path, srv)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	ts := httptest.NewServer(mux)

	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})
	return ts.URL, priv.Public()
}

// The whole feature: two nodes meet on a relay that shares a port with a web
// server, and a packet crosses between them.
func TestForwardsThroughAWebServer(t *testing.T) {
	base, relayKey := webRelayServer(t)
	url := Resolve(Path, base)

	a, aKey := connect(t, url, relayKey)
	b, bKey := connect(t, url, relayKey)

	payload := []byte("an already-encrypted wireguard packet")
	if err := a.Send(bKey, payload); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := b.Recv(ctx)
	if err != nil {
		t.Fatalf("b never received the packet: %v", err)
	}
	if !bytes.Equal(p.Data, payload) || p.Src != aKey {
		t.Errorf("got %q from %s, want %q from %s", p.Data, p.Src, payload, aKey)
	}
}

// Carrying a relay must not cost the web server its other routes: the control
// plane still has nodes to answer on the same port.
func TestTheWebServerKeepsServingBesideTheRelay(t *testing.T) {
	base, relayKey := webRelayServer(t)
	connect(t, Resolve(Path, base), relayKey)

	resp, err := http.Get(base + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Errorf("health answered %s %q while relaying", resp.Status, body)
	}
}

// Somebody opening the relay's URL in a browser gets told what it is, not a
// hijacked connection.
func TestAPlainRequestIsNotUpgraded(t *testing.T) {
	base, _ := webRelayServer(t)

	resp, err := http.Get(base + Path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Errorf("a plain GET got %s, want 426", resp.Status)
	}
}

// Pointed at a web server with no relay behind the path, the client has to say
// so rather than hang or report a handshake failure that blames the relay.
func TestNoRelayBehindThePathIsReported(t *testing.T) {
	base, relayKey := webRelayServer(t)
	nodeKey, _ := key.NewPrivate()

	c := NewClient(base+"/health", relayKey, nodeKey)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.dial(ctx)
	if err == nil || !strings.Contains(err.Error(), "no relay at") {
		t.Errorf("dial = %v, want a no-relay error", err)
	}
}

// The relay key is pinned on this path exactly as on the bare port: whatever
// answers at the URL has to hold the key the control plane named.
func TestWebRelayKeyIsPinned(t *testing.T) {
	base, _ := webRelayServer(t)
	wrong, _ := key.NewPrivate()
	nodeKey, _ := key.NewPrivate()

	c := NewClient(Resolve(Path, base), wrong.Public(), nodeKey)
	c.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := c.session(ctx); err == nil || !strings.Contains(err.Error(), "relay key mismatch") {
		t.Errorf("session = %v, want a key mismatch", err)
	}
}

// upgradeFrom asks the web relay at base for an upgrade, as a proxy that says
// it is forwarding for xff, and reports whether the relay took it.
func upgradeFrom(t *testing.T, base, xff string) bool {
	t.Helper()
	host := strings.TrimPrefix(base, "http://")
	c, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: %s\r\nConnection: Upgrade\r\nX-Forwarded-For: %s\r\n\r\n",
		Path, host, UpgradeProto, xff)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	return err == nil && resp.StatusCode == http.StatusSwitchingProtocols
}

// Behind a reverse proxy on the same machine — the httptest server's clients
// are on loopback, as cloudflared or Caddy would be — every node arrives from
// the proxy's address. The handshake limit used to count the proxy, so
// twenty nodes redialling at once, a fleet restarting, spent it for all of
// them, and any stranger reaching the proxy could do the same.
func TestNodesBehindAProxyDoNotShareOneHandshakeBudget(t *testing.T) {
	base, _ := webRelayServer(t)

	for i := range 2 * handshakeBurst {
		if !upgradeFrom(t, base, fmt.Sprintf("198.51.100.%d", i+1)) {
			t.Fatalf("node %d behind the proxy was refused", i+1)
		}
	}
}

// With no proxy trusted, the header is ignored: anybody can write it, and a
// relay that believed it would give every connection a fresh budget.
func TestAnUntrustedForwardedForIsIgnored(t *testing.T) {
	base, _ := webRelayServerWith(t, func(s *Server) { s.SetTrustedProxies(nil) })

	refused := false
	for i := range handshakeBurst + 1 {
		if !upgradeFrom(t, base, fmt.Sprintf("198.51.100.%d", i+1)) {
			refused = true
		}
	}
	if !refused {
		t.Error("naming a new address each time got past the handshake limit")
	}
}

func TestResolve(t *testing.T) {
	cases := []struct{ relay, control, want string }{
		{"/relay", "http://192.168.1.20:8080", "http://192.168.1.20:8080/relay"},
		{"/relay", "http://tenet.duckdns.org:8080/", "http://tenet.duckdns.org:8080/relay"},
		{"/relay", "https://makima.example.dev", "https://makima.example.dev/relay"},
		// Absolute relays are an operator's choice and are left alone.
		{"relay.example:3478", "http://192.168.1.20:8080", "relay.example:3478"},
		// With no control plane — a paired node — there is nothing to resolve
		// against, and the relative URL is left for DialAddr to refuse.
		{"/relay", "", "/relay"},
	}
	for _, c := range cases {
		if got := Resolve(c.relay, c.control); got != c.want {
			t.Errorf("Resolve(%q, %q) = %q, want %q", c.relay, c.control, got, c.want)
		}
	}
}

// Which addresses mean "a web server is in front of this relay". The http://
// forms without a path must keep meaning the bare relay port, as they always
// have.
func TestWebRelayForms(t *testing.T) {
	cases := []struct {
		in   string
		web  bool
		dial string
	}{
		{"http://tenet:8080/relay", true, "tenet:8080"},
		{"http://tenet/relay", true, "tenet:80"},
		{"https://makima.example.dev/relay", true, "makima.example.dev:443"},
		{"https://makima.example.dev", true, "makima.example.dev:443"},
		{"http://relay.example.com", false, "relay.example.com:3478"},
		{"http://relay.example.com:8080", false, "relay.example.com:8080"},
		{"relay.example.com:3478", false, "relay.example.com:3478"},
	}
	for _, c := range cases {
		if _, web := webRelay(c.in); web != c.web {
			t.Errorf("webRelay(%q) = %v, want %v", c.in, web, c.web)
		}
		got, err := DialAddr(c.in)
		if err != nil || got != c.dial {
			t.Errorf("DialAddr(%q) = %q, %v, want %q", c.in, got, err, c.dial)
		}
	}

	if _, err := DialAddr("/relay"); err == nil {
		t.Error("an unresolved relative relay was accepted")
	}
}
