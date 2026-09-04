package magicsock

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/pair"
	"golang.zx2c4.com/wireguard/conn"
)

// pump runs a Conn's receive functions the way WireGuard would.
//
// Disco traffic — probes and knocks alike — is consumed inside the receive
// loop and never returned, so a pairing only progresses while something is
// actually reading. In the daemon that something is WireGuard.
func pump(t *testing.T, c *Conn) {
	t.Helper()
	fns, _, err := c.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range fns {
		go func() {
			bufs := [][]byte{make([]byte, 1500)}
			sizes := make([]int, 1)
			eps := make([]conn.Endpoint, 1)
			for {
				if _, err := fn(bufs, sizes, eps); err != nil {
					return
				}
			}
		}()
	}
}

// listen opens a pairing window and returns the address to knock on, plus a
// channel carrying whoever knocks.
func listen(t *testing.T, c *Conn, nodeKey, discoKey key.Private, relayURL string, relayKey key.Public) (pair.Address, chan PairedPeer) {
	t.Helper()

	addr := pair.MeshAddr(nodeKey.Public())
	a := pair.Address{
		NodeKey:  nodeKey.Public(),
		DiscoKey: discoKey.Public(),
		Addr:     addr,
		Name:     "listener",
		Relay:    relayURL,
		RelayKey: relayKey,
	}
	if relayURL == "" {
		a.Endpoints = []netip.AddrPort{
			netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), c.LocalPort()),
		}
	}

	got := make(chan PairedPeer, 4)
	c.SetPairing(&Pairing{
		Token: pair.Token(a),
		Self:  PairingSelf{Addr: addr, Name: "listener"},
		Until: time.Now().Add(time.Minute),
		Accept: func(p PairedPeer) error {
			got <- p
			return nil
		},
	})
	return a, got
}

// Two machines with no control plane between them become peers, over UDP,
// knowing nothing but a pasted string.
func TestPairingOverUDP(t *testing.T) {
	a, aNode, aDisco := newConn(t)
	b, bNode, bDisco := newConn(t)
	_ = bDisco
	pump(t, a)
	pump(t, b)

	addr, knocked := listen(t, a, aNode, aDisco, "", key.Public{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	self := PairingSelf{Addr: pair.MeshAddr(bNode.Public()), Name: "knocker"}
	peer, err := b.Knock(ctx, addr, self)
	if err != nil {
		t.Fatalf("knock: %v", err)
	}

	// What the knocker learned about the listener.
	if peer.NodeKey != aNode.Public() {
		t.Error("the acknowledgement named the wrong node key")
	}
	if peer.DiscoKey != aDisco.Public() {
		t.Error("the acknowledgement named the wrong disco key")
	}
	if peer.Addr != pair.MeshAddr(aNode.Public()) {
		t.Errorf("the listener claimed %s, want its derived address %s", peer.Addr, pair.MeshAddr(aNode.Public()))
	}
	if peer.Name != "listener" {
		t.Errorf("the listener called itself %q", peer.Name)
	}

	// And what the listener learned about the knocker.
	select {
	case got := <-knocked:
		if got.NodeKey != bNode.Public() {
			t.Error("the listener recorded the wrong node key for the knocker")
		}
		if got.Addr != pair.MeshAddr(bNode.Public()) {
			t.Errorf("the listener recorded address %s for the knocker", got.Addr)
		}
		// A knock that arrived over UDP proves the address it came from
		// reaches the sender, which no advertised hint can.
		if len(got.Endpoints) == 0 {
			t.Error("a knock over UDP taught the listener no endpoint at all")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the listener never saw the knock it acknowledged")
	}
}

// The same exchange with no direct path at all: both ends meet at a relay,
// keyed by public key and nothing else.
func TestPairingOverRelay(t *testing.T) {
	relayAddr, relayKey := testRelay(t)

	a, aNode, aDisco := newConn(t)
	b, bNode, _ := newConn(t)
	pump(t, a)
	pump(t, b)

	// Only the listener is on the relay to begin with. The knocker adopts it
	// from the address, which is the whole point: it has no control plane to
	// be assigned one by.
	a.setRelay(relayAddr, relayKey)
	waitRelay(t, a)

	addr, knocked := listen(t, a, aNode, aDisco, relayAddr, relayKey)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	self := PairingSelf{Addr: pair.MeshAddr(bNode.Public()), Name: "knocker"}
	peer, err := b.Knock(ctx, addr, self)
	if err != nil {
		t.Fatalf("knock over relay: %v", err)
	}
	if peer.NodeKey != aNode.Public() {
		t.Error("the acknowledgement named the wrong node key")
	}
	if b.RelayURL() != relayAddr {
		t.Errorf("the knocker is on relay %q, want the one from the address", b.RelayURL())
	}

	select {
	case got := <-knocked:
		if got.NodeKey != bNode.Public() {
			t.Error("the listener recorded the wrong node key")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the listener never saw the knock it acknowledged")
	}
}

// A knock carrying the wrong token is answered with silence — not a refusal,
// which would confirm that this machine runs makima and is merely not
// listening to this caller.
func TestKnockWithAWrongTokenGetsNothing(t *testing.T) {
	a, aNode, aDisco := newConn(t)
	b, bNode, _ := newConn(t)
	pump(t, a)
	pump(t, b)

	addr, knocked := listen(t, a, aNode, aDisco, "", key.Public{})

	// The knocker holds a real address but the wrong preshared key, which is
	// exactly the case a preshared key exists to catch: it has the disco key
	// — from a screenshot, a log, a shoulder — and not the secret.
	psk, err := key.NewShared()
	if err != nil {
		t.Fatal(err)
	}
	wrong := addr
	wrong.PSK = psk

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := b.Knock(ctx, wrong, PairingSelf{Addr: pair.MeshAddr(bNode.Public())}); err == nil {
		t.Fatal("a knock with the wrong token was acknowledged")
	}
	select {
	case p := <-knocked:
		t.Fatalf("a knock with the wrong token reached the accept callback: %+v", p)
	default:
	}
}

// With no pairing window open a machine answers nothing, which is what makes
// publishing an address safe once the window has closed.
func TestKnockAtAClosedWindowGetsNothing(t *testing.T) {
	a, aNode, aDisco := newConn(t)
	b, bNode, _ := newConn(t)
	pump(t, a)
	pump(t, b)

	addr, _ := listen(t, a, aNode, aDisco, "", key.Public{})
	a.SetPairing(nil)

	if a.PairingOpen() {
		t.Fatal("the pairing window reports itself open after being closed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := b.Knock(ctx, addr, PairingSelf{Addr: pair.MeshAddr(bNode.Public())}); err == nil {
		t.Fatal("a knock at a closed window was acknowledged")
	}
}

// An expired window is a closed one. Nothing has to sweep it: the check is on
// the receive side, so a machine left running overnight stops answering on its
// own.
func TestPairingWindowExpires(t *testing.T) {
	a, aNode, aDisco := newConn(t)
	b, bNode, _ := newConn(t)
	pump(t, a)
	pump(t, b)

	addr, _ := listen(t, a, aNode, aDisco, "", key.Public{})

	p := &Pairing{
		Token:  pair.Token(addr),
		Self:   PairingSelf{Addr: pair.MeshAddr(aNode.Public())},
		Until:  time.Now().Add(-time.Second),
		Accept: func(PairedPeer) error { return nil },
	}
	a.SetPairing(p)

	if a.PairingOpen() {
		t.Error("an expired pairing window reports itself open")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := b.Knock(ctx, addr, PairingSelf{Addr: pair.MeshAddr(bNode.Public())}); err == nil {
		t.Fatal("a knock at an expired window was acknowledged")
	}
}

// Knocking on your own address is a paste error, and it must fail as one
// rather than deadlocking against a machine that cannot answer itself.
func TestKnockingAtYourselfIsRefused(t *testing.T) {
	a, aNode, aDisco := newConn(t)
	pump(t, a)

	addr, _ := listen(t, a, aNode, aDisco, "", key.Public{})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := a.Knock(ctx, addr, PairingSelf{}); err == nil {
		t.Fatal("a machine paired with itself")
	}
}
