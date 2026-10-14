package control

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/bypass"
	"github.com/justin06lee/makima/internal/invite"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/relay"
	"github.com/justin06lee/makima/internal/tor"
)

// TestNodeAwayFromHome is a node whose home address answers nothing — the
// laptop has left the house — joining, polling and reaching the relay
// through nothing but the server's onion address: two real tors, the
// server's publishing and the node's dialling. It needs tor installed and
// the tor network: MAKIMA_TOR_E2E=1 go test ./internal/control -run Away
func TestNodeAwayFromHome(t *testing.T) {
	if os.Getenv("MAKIMA_TOR_E2E") == "" {
		t.Skip("set MAKIMA_TOR_E2E=1 to run against a real tor")
	}
	if _, err := tor.Find(); err != nil {
		t.Skip(err)
	}
	logger := log.New(os.Stderr, "", log.Ltime)

	// The server, with its relay on the same port, published as an onion
	// service the way makima-server serve publishes it.
	store, err := OpenStore(filepath.Join(t.TempDir(), "control.json"))
	if err != nil {
		t.Fatal(err)
	}
	relayKey, _ := key.NewPrivate()
	rs := relay.NewServer(relayKey, logger)
	defer rs.Close()
	handlers := NewServer(store, logger)
	handlers.SetRelay(rs)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handlers.Handler()}
	go srv.Serve(ln)
	defer srv.Close()

	onionKey, err := tor.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetOnion(onionKey.Host()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	published := make(chan struct{})
	svc := &tor.Service{
		DataDir: t.TempDir(), Key: onionKey, VirtPort: 80, Target: ln.Addr().String(), Logger: logger,
		OnState: func(st tor.ServiceState) {
			store.NoteTor(st)
			if st.Phase == tor.PhaseReachable {
				close(published)
			}
		},
	}
	go svc.Run(ctx)
	select {
	case <-published:
	case <-ctx.Done():
		t.Fatalf("never published: %+v", store.TorState())
	}

	// The node: its home address is a port nothing listens on.
	auth, err := store.MintAuthKey(false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &tor.Dialer{DataDir: t.TempDir(), Logger: logger}
	defer dialer.Close()
	b := &bypass.Binder{}
	b.SetOnion(dialer.DialContext)

	const home = "http://127.0.0.1:1"
	start := time.Now()
	srvKey, err := FetchServerKey(ctx, b, OnionURL(onionKey.Host()))
	if err != nil {
		t.Fatal(err)
	}
	if srvKey != store.ServerKey().Public() {
		t.Fatal("the onion address answered with somebody else's key")
	}
	t.Logf("server key over tor in %s", time.Since(start).Round(time.Millisecond))

	machineKey, _ := key.NewPrivate()
	nodeKey, _ := key.NewPrivate()
	discoKey, _ := key.NewPrivate()
	c := NewClient(home, srvKey, machineKey)
	c.SetBinder(b)
	c.SetAlternates([]string{OnionURL(onionKey.Host())})

	start = time.Now()
	if _, err := c.Register(ctx, &RegisterRequest{
		Name: "laptop", NodeKey: nodeKey.Public(), DiscoKey: discoKey.Public(), AuthKey: auth.Secret,
	}); err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != OnionURL(onionKey.Host()) {
		t.Errorf("registered, but the client is on %s", c.BaseURL())
	}
	m, err := c.PollMap(ctx, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("registered and polled over tor in %s", time.Since(start).Round(time.Millisecond))
	if m.Self.Name != "laptop" {
		t.Errorf("netmap is for %q", m.Self.Name)
	}

	// The relay, resolved against the address the node reaches the server
	// at, as the daemon resolves it.
	relayURL := relay.Resolve(m.HomeRelay.URL, c.BaseURL())
	rc := relay.NewClient(relayURL, m.HomeRelay.Key, nodeKey)
	rc.SetDialer(b.DialContext)
	rc.SetLogger(logger)
	connected := make(chan struct{}, 1)
	rc.OnStateChange(func(up bool) {
		if up {
			select {
			case connected <- struct{}{}:
			default:
			}
		}
	})
	rctx, stopRelay := context.WithCancel(ctx)
	defer stopRelay()
	go rc.Run(rctx)
	start = time.Now()
	select {
	case <-connected:
		t.Logf("relay %s connected over tor in %s", relayURL, time.Since(start).Round(time.Millisecond))
	case <-ctx.Done():
		t.Fatalf("relay %s never connected", relayURL)
	}
	rc.Close()

	// Fifteen words, typed on a machine somewhere else. They carry no onion
	// address; they lead to one of the invite's own, which the server
	// publishes the moment the invite is minted.
	secret, err := invite.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	seed := invite.JoinOnionSeed(secret)
	if _, err := store.MintInviteKey(invite.AuthKey(secret), invite.Handle(secret), invite.MACKey(secret), seed[:], time.Hour); err != nil {
		t.Fatal(err)
	}
	svc.SetExtra(store.JoinOnions())
	words, err := invite.EncodeWords(home, secret)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := invite.Parse(words)
	if err != nil {
		t.Fatal(err)
	}
	joinURL := OnionURL(inv.Onion)
	handle, macKey, _ := inv.Verifier()

	start = time.Now()
	var wordsKey key.Public
	for {
		wordsKey, err = FetchServerKeyVerified(ctx, b, joinURL, handle, macKey)
		var de *tor.DialError
		if err == nil || !errors.As(err, &de) || !de.Unpublished() {
			break
		}
		t.Logf("the invite's onion address is not published yet")
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		t.Fatal(err)
	}
	if wordsKey != store.ServerKey().Public() {
		t.Fatal("the invite's onion address vouched for somebody else's key")
	}
	t.Logf("server key by the words' own onion address in %s", time.Since(start).Round(time.Millisecond))

	desk, _ := key.NewPrivate()
	deskNode, _ := key.NewPrivate()
	wc := NewClient(home, wordsKey, desk)
	wc.SetBinder(b)
	wc.SetAlternates([]string{joinURL})
	resp, err := wc.Register(ctx, &RegisterRequest{
		Name: "desk", NodeKey: deskNode.Public(), DiscoKey: deskNode.Public(), AuthKey: inv.AuthKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	// What the machine keeps: the server's lasting onion address, not the
	// invite's, which goes when the invite does.
	if !slices.Contains(resp.ControlURLs, OnionURL(onionKey.Host())) {
		t.Errorf("registration named %v, not the server's onion address", resp.ControlURLs)
	}
	t.Logf("joined by words, from anywhere, in %s", time.Since(start).Round(time.Millisecond))
}
