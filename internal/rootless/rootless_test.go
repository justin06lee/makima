package rootless

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/pair"
)

func quiet() *log.Logger { return log.New(io.Discard, "", 0) }

func node(t *testing.T, name string) *Node {
	t.Helper()
	n, err := New(Options{Name: name, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	return n
}

// The claim this whole mode rests on: a working WireGuard tunnel with no root,
// no interface, no route and no firewall rule. If this test can run as an
// ordinary user, so can the feature.
func TestATunnelWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root, which proves less than it could — the same code path is taken either way")
	}

	server := node(t, "server")
	client := node(t, "client")

	// Something ordinary listening on the server machine.
	backend := httptest("hello from the other side")
	t.Cleanup(func() { backend.Close() })

	_, backendPort, err := net.SplitHostPort(backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Published on the mesh at 8080, which exists only inside these two
	// processes: nothing is bound on any real interface.
	if err := server.Expose(ctx, 8080, backend.Addr().String()); err != nil {
		t.Fatal(err)
	}

	addr, err := server.Address(key.Shared{})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := server.Listen(ctx, addr, time.Now().Add(20*time.Second))
		done <- err
	}()

	peer, err := client.Knock(ctx, addr)
	if err != nil {
		t.Fatalf("knock: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("listen: %v", err)
	}

	peerAddr, err := peer.Addr()
	if err != nil {
		t.Fatal(err)
	}
	if peerAddr != server.Addr() {
		t.Errorf("paired with %s, want %s", peerAddr, server.Addr())
	}

	// Through the tunnel, entirely in userspace on both ends.
	conn, err := dialWithRetry(ctx, client, netip.AddrPortFrom(peerAddr, 8080))
	if err != nil {
		t.Fatalf("dial through the tunnel: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if want := "hello from the other side"; !contains(string(body), want) {
		t.Errorf("got %q, want it to contain %q", body, want)
	}
	_ = backendPort
}

// The other half: a local port on the client that comes out on the server,
// so an ordinary program can use the tunnel without knowing it exists.
func TestForwardALocalPort(t *testing.T) {
	server := node(t, "server")
	client := node(t, "client")

	backend := httptest("forwarded")
	t.Cleanup(func() { backend.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Expose(ctx, 9000, backend.Addr().String()); err != nil {
		t.Fatal(err)
	}

	addr, err := server.Address(key.Shared{})
	if err != nil {
		t.Fatal(err)
	}
	go server.Listen(ctx, addr, time.Now().Add(20*time.Second))

	peer, err := client.Knock(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	peerAddr, _ := peer.Addr()

	local, err := client.Forward(ctx, "127.0.0.1:0", peerAddr, 9000)
	if err != nil {
		t.Fatal(err)
	}

	// An ordinary HTTP client, on an ordinary loopback address.
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := getWithRetry(c, "http://"+local+"/")
	if err != nil {
		t.Fatalf("through the forwarded port: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(body), "forwarded") {
		t.Errorf("got %q", body)
	}
}

// A preshared key in the address must gate the pairing here too.
func TestPresharedKeyIsEnforced(t *testing.T) {
	server := node(t, "server")
	client := node(t, "client")

	psk, err := key.NewShared()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addr, err := server.Address(psk)
	if err != nil {
		t.Fatal(err)
	}
	go server.Listen(ctx, addr, time.Now().Add(8*time.Second))

	// The same address without the secret.
	without := addr
	without.PSK = key.Shared{}

	knockCtx, cancelKnock := context.WithTimeout(ctx, 2*time.Second)
	defer cancelKnock()
	if _, err := client.Knock(knockCtx, without); err == nil {
		t.Fatal("pairing succeeded without the preshared key")
	}
}

// Every node's address comes from its own key, so two of them never collide by
// accident and neither has to be told what to be.
func TestAddressIsDerivedFromTheKey(t *testing.T) {
	a := node(t, "a")
	b := node(t, "b")

	if a.Addr() == b.Addr() {
		t.Error("two nodes derived the same address")
	}
	if !pair.InMesh(a.Addr()) {
		t.Errorf("%s is outside the mesh range", a.Addr())
	}
}

// A pairing address has to name somewhere to meet, or it is not usable. With
// no relay that means a real endpoint, which a machine on any network has.
func TestAddressCarriesSomewhereToMeet(t *testing.T) {
	n := node(t, "solo")

	a, err := n.Address(key.Shared{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Relay == "" && len(a.Endpoints) == 0 {
		t.Skip("this machine has no non-loopback address, so there is nowhere to meet")
	}
	if _, err := pair.Encode(a); err != nil {
		t.Errorf("the address will not encode: %v", err)
	}
}

// httptest starts a plain HTTP server on loopback.
func httptest(body string) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body)
	}))
	return ln
}

// dialWithRetry allows for the tunnel's first handshake, which happens on the
// first packet rather than at pairing time.
func dialWithRetry(ctx context.Context, n *Node, dst netip.AddrPort) (net.Conn, error) {
	var lastErr error
	for range 40 {
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		c, err := n.Dial(dialCtx, dst)
		cancel()
		if err == nil {
			return c, nil
		}
		lastErr = err
		select {
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func getWithRetry(c *http.Client, url string) (*http.Response, error) {
	var lastErr error
	for range 40 {
		resp, err := c.Get(url)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	return nil, lastErr
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
