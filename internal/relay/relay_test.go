package relay

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// testRelay starts a real relay on a real port and returns its address.
func testRelay(t *testing.T) (*Server, string, key.Public) {
	t.Helper()

	priv, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(priv, log.New(io.Discard, "", 0))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)

	t.Cleanup(func() {
		ln.Close()
		srv.Close()
	})
	return srv, ln.Addr().String(), priv.Public()
}

// connect brings up a client and waits for its session to establish.
func connect(t *testing.T, addr string, relayKey key.Public) (*Client, key.Public) {
	t.Helper()

	nodeKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	c := NewClient(addr, relayKey, nodeKey)
	c.SetLogger(log.New(io.Discard, "", 0))

	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	t.Cleanup(func() {
		cancel()
		c.Close()
	})

	waitConnected(t, c)
	return c, nodeKey.Public()
}

func waitConnected(t *testing.T, c *Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.Connected() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("client never connected to the relay")
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("the relay never reads this")

	if err := writeFrame(&buf, frameSendPacket, payload); err != nil {
		t.Fatal(err)
	}

	got, data, err := readFrame(&buf, make([]byte, maxFrameSize))
	if err != nil {
		t.Fatal(err)
	}
	if got != frameSendPacket {
		t.Errorf("frame type %d, want %d", got, frameSendPacket)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("payload %q, want %q", data, payload)
	}
}

// A zero-length frame is legitimate — a ping with no payload — and must not be
// confused with a closed connection.
func TestEmptyFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, framePing, nil); err != nil {
		t.Fatal(err)
	}

	got, data, err := readFrame(&buf, make([]byte, maxFrameSize))
	if err != nil {
		t.Fatal(err)
	}
	if got != framePing || len(data) != 0 {
		t.Errorf("got type %d with %d bytes, want a ping with none", got, len(data))
	}
}

// An oversized length must be refused outright rather than allocated for.
func TestOversizedFrameRefused(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{byte(frameSendPacket), 0xff, 0xff, 0xff, 0xff})

	if _, _, err := readFrame(&buf, make([]byte, maxFrameSize)); err == nil {
		t.Error("a frame claiming 4GB was accepted")
	}
}

// The point of the relay: two nodes that never address each other directly
// still exchange packets.
func TestForwardsBetweenClients(t *testing.T) {
	_, addr, relayKey := testRelay(t)

	a, _ := connect(t, addr, relayKey)
	b, bKey := connect(t, addr, relayKey)

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
	if !bytes.Equal(p.Data, payload) {
		t.Errorf("payload %q, want %q", p.Data, payload)
	}
}

// The routing header must be rewritten from destination to source, or the
// receiver has no way to attribute the packet to a peer.
func TestForwardedPacketNamesItsSender(t *testing.T) {
	_, addr, relayKey := testRelay(t)

	a, aKey := connect(t, addr, relayKey)
	b, bKey := connect(t, addr, relayKey)

	if err := a.Send(bKey, []byte("x")); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, err := b.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.Src != aKey {
		t.Errorf("packet claims to be from %s, want %s", p.Src, aKey)
	}
}

// A client that pins the wrong relay key must refuse the connection. Without
// this, anything answering on the address could silently blackhole every
// relayed packet.
func TestWrongRelayKeyRefused(t *testing.T) {
	_, addr, _ := testRelay(t)

	impostor, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	c := NewClient(addr, impostor.Public(), nodeKey)
	c.SetLogger(log.New(io.Discard, "", 0))
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go c.Run(ctx)

	time.Sleep(300 * time.Millisecond)
	if c.Connected() {
		t.Error("a client connected to a relay whose key it did not expect")
	}
}

// A connection that never completes the handshake must not end up in the
// routing table.
func TestGarbageHandshakeRejected(t *testing.T) {
	srv, addr, _ := testRelay(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Read the greeting and hello, then answer with nonsense.
	io.CopyN(io.Discard, conn, 8)
	conn.Write([]byte{byte(frameClientHello), 0, 0, 0, 4, 'j', 'u', 'n', 'k'})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Stats().Rejected.Load() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if srv.ConnectedCount() != 0 {
		t.Errorf("%d client(s) registered after a failed handshake", srv.ConnectedCount())
	}
	if srv.Stats().Rejected.Load() == 0 {
		t.Error("the failed handshake was not counted as a rejection")
	}
}

// A packet for a node that is not connected is dropped, not queued and not an
// error: the sender will fall back to a direct path or retry.
func TestPacketForAbsentNodeIsDropped(t *testing.T) {
	srv, addr, relayKey := testRelay(t)
	a, _ := connect(t, addr, relayKey)

	absent, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(absent.Public(), []byte("nobody home")); err != nil {
		t.Fatalf("sending to an absent node should not error: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Stats().Dropped.Load() > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("the undeliverable packet was not counted as dropped")
}

// A node reconnecting — a laptop that changed networks — must displace its old
// connection rather than sit beside it, or forwarding races between a live
// socket and a dead one.
func TestReconnectDisplacesOldSession(t *testing.T) {
	srv, addr, relayKey := testRelay(t)

	nodeKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	first := NewClient(addr, relayKey, nodeKey)
	first.SetLogger(log.New(io.Discard, "", 0))
	ctx1, cancel1 := context.WithCancel(context.Background())
	go first.Run(ctx1)
	waitConnected(t, first)

	second := NewClient(addr, relayKey, nodeKey)
	second.SetLogger(log.New(io.Discard, "", 0))
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer func() {
		cancel1()
		cancel2()
		first.Close()
		second.Close()
	}()
	go second.Run(ctx2)
	waitConnected(t, second)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.ConnectedCount() == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("%d connections for one node key; the reconnect did not displace the original", srv.ConnectedCount())
}

func TestDialAddrForms(t *testing.T) {
	cases := []struct{ in, want string }{
		{"relay.example.com", "relay.example.com:3478"},
		{"relay.example.com:9999", "relay.example.com:9999"},
		{"http://relay.example.com", "relay.example.com:3478"},
		{"http://relay.example.com:8080", "relay.example.com:8080"},
		{"192.0.2.1:3478", "192.0.2.1:3478"},
	}
	for _, c := range cases {
		got, err := DialAddr(c.in)
		if err != nil {
			t.Errorf("DialAddr(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("DialAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	if _, err := DialAddr(""); err == nil {
		t.Error("an empty relay address was accepted")
	}
}
