package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// dialTimeout bounds a single connection attempt.
const dialTimeout = 10 * time.Second

// recvQueue buffers packets between the read loop and whoever is calling Recv.
//
// Depth here trades latency for loss under burst. A relayed path is already
// the slow one, so a little buffering is worth more than the handful of
// milliseconds it can add.
const recvQueue = 256

// keepaliveInterval is how often an idle client pings the relay.
//
// A relayed connection can legitimately carry no traffic for minutes, and a
// NAT between node and relay will drop an idle TCP mapping without telling
// either end. The ping is what turns "silently unreachable" into "connection
// error, reconnect".
const keepaliveInterval = 30 * time.Second

// Packet is one relayed WireGuard packet and the node that sent it.
type Packet struct {
	Src  key.Public
	Data []byte
}

// Client is a node's connection to one relay.
//
// It reconnects on its own. A relay going away must not take the mesh with it:
// the node keeps trying in the background while direct paths carry on working,
// and relayed peers become reachable again the moment it returns.
type Client struct {
	url      string
	relayKey key.Public
	nodeKey  key.Private
	log      *log.Logger

	recv chan Packet

	mu        sync.Mutex
	conn      net.Conn
	connected bool

	closeOnce sync.Once
	closed    chan struct{}

	// notify fires whenever the connection state changes, so a caller can log
	// it or re-evaluate path selection without polling.
	notify func(connected bool)
}

// NewClient prepares a connection to a relay. It does not dial; call Run.
func NewClient(relayURL string, relayKey key.Public, nodeKey key.Private) *Client {
	return &Client{
		url:      relayURL,
		relayKey: relayKey,
		nodeKey:  nodeKey,
		log:      log.Default(),
		recv:     make(chan Packet, recvQueue),
		closed:   make(chan struct{}),
	}
}

// SetLogger redirects this client's diagnostics. It must be set before Run.
func (c *Client) SetLogger(l *log.Logger) {
	if l != nil {
		c.log = l
	}
}

// OnStateChange registers a callback for connect and disconnect. It must be
// set before Run.
func (c *Client) OnStateChange(fn func(connected bool)) { c.notify = fn }

// URL is the relay this client talks to.
func (c *Client) URL() string { return c.url }

// Connected reports whether a session is currently established.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Run maintains the connection until ctx is cancelled or Close is called.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		default:
		}

		err := c.session(ctx)

		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		default:
		}

		if err != nil && !errors.Is(err, context.Canceled) {
			// One line per failed attempt would be a torrent while a relay is
			// down for an hour. The backoff is included so a reader can see the
			// retry is slowing rather than spinning.
			c.log.Printf("relay %s: %v (retrying in %s)", c.url, err, backoff)
		}

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		}
		// Capped, because a relay that has been down for an hour should not
		// mean an hour's delay noticing it came back.
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// session runs one connection from dial to disconnect.
func (c *Client) session(ctx context.Context) error {
	addr, err := DialAddr(c.url)
	if err != nil {
		return err
	}

	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	if err := c.handshake(conn); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	c.setConn(conn)
	defer c.setConn(nil)

	// The keepalive and the read loop share the connection's lifetime: closing
	// it from either side unblocks the other.
	done := make(chan struct{})
	defer close(done)
	go c.keepalive(conn, done)

	// A context cancellation has to reach a goroutine parked in Read, and the
	// only way to do that is to close the socket under it.
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-c.closed:
			conn.Close()
		case <-done:
		}
	}()

	return c.readLoop(conn)
}

// handshake proves possession of our node key to the relay.
func (c *Client) handshake(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})

	var got [8]byte
	if _, err := readFull(conn, got[:]); err != nil {
		return err
	}
	if got != magic {
		return errors.New("not a makima relay (wrong greeting)")
	}

	buf := make([]byte, maxFrameSize)
	t, payload, err := readFrame(conn, buf)
	if err != nil {
		return err
	}
	if t != frameServerHello {
		return errors.New("expected a server hello")
	}

	var sh serverHello
	if err := json.Unmarshal(payload, &sh); err != nil {
		return err
	}
	if sh.Version != ProtocolVersion {
		return fmt.Errorf("relay speaks protocol %d, we speak %d", sh.Version, ProtocolVersion)
	}
	if len(sh.Challenge) != challengeSize {
		return errors.New("malformed challenge")
	}

	// Pinning matters: without it a machine on the path could answer as the
	// relay and become a black hole for every relayed packet. It cannot read
	// them — they are WireGuard-encrypted — but it can silently discard them,
	// and a node would have no way to tell that from an idle peer.
	if !c.relayKey.IsZero() && sh.RelayKey != c.relayKey {
		return fmt.Errorf("relay key mismatch: it presented %s, we expected %s", sh.RelayKey, c.relayKey)
	}

	nonce, sealed, err := key.Seal(sh.Challenge, sh.RelayKey, c.nodeKey)
	if err != nil {
		return err
	}
	hello, err := json.Marshal(clientHello{
		Version: ProtocolVersion,
		NodeKey: c.nodeKey.Public(),
		Nonce:   nonce,
		Sealed:  sealed,
	})
	if err != nil {
		return err
	}
	if err := writeFrame(conn, frameClientHello, hello); err != nil {
		return err
	}
	return c.confirmRegistered(conn, buf)
}

// confirmRegistered waits until the relay has actually put us in its routing
// table.
//
// Having written a hello is not the same as being reachable. The relay
// registers a client only after it has read and verified that hello, so
// between the write and the read there is a window in which we believe we are
// connected and packets addressed to us are being dropped as undeliverable.
//
// A ping closes it. The relay only answers pings from its read loop, which
// starts after registration, so a pong is proof that we are in the table —
// using frames the protocol already has rather than adding a handshake step.
func (c *Client) confirmRegistered(conn net.Conn, buf []byte) error {
	var payload [8]byte
	if err := writeFrame(conn, framePing, payload[:]); err != nil {
		return err
	}

	for {
		t, data, err := readFrame(conn, buf)
		if err != nil {
			return err
		}
		switch t {
		case framePong:
			return nil

		case frameRecvPacket:
			// A peer was already sending to us. Dropping these would lose real
			// traffic at the exact moment a session is being established, which
			// is when loss is least affordable.
			if len(data) < keySize {
				continue
			}
			var src key.Public
			copy(src[:], data[:keySize])
			packet := make([]byte, len(data)-keySize)
			copy(packet, data[keySize:])

			select {
			case c.recv <- Packet{Src: src, Data: packet}:
			default:
			}
		}
	}
}

func (c *Client) readLoop(conn net.Conn) error {
	buf := make([]byte, maxFrameSize)

	for {
		t, payload, err := readFrame(conn, buf)
		if err != nil {
			return err
		}

		switch t {
		case frameRecvPacket:
			if len(payload) < keySize {
				continue
			}
			var src key.Public
			copy(src[:], payload[:keySize])

			// Copied out of the read buffer, which the next iteration reuses.
			data := make([]byte, len(payload)-keySize)
			copy(data, payload[keySize:])

			select {
			case c.recv <- Packet{Src: src, Data: data}:
			default:
				// Nobody is draining fast enough. Dropping is correct: the
				// alternative is stalling the read loop, which would back
				// pressure onto the relay and hurt every other peer.
			}

		case framePong:
			// Liveness confirmed by the read itself; nothing more to do.

		default:
		}
	}
}

func (c *Client) keepalive(conn net.Conn, done <-chan struct{}) {
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()

	var payload [8]byte
	for {
		select {
		case <-t.C:
			c.mu.Lock()
			cur := c.conn
			c.mu.Unlock()
			if cur != conn {
				return
			}
			if err := c.writeFrameLocked(framePing, payload[:]); err != nil {
				conn.Close()
				return
			}
		case <-done:
			return
		case <-c.closed:
			return
		}
	}
}

// Send forwards a packet to another node through the relay.
//
// Returns an error when no session is established, which the caller is
// expected to treat as "this path is unavailable right now" rather than as a
// fatal condition — a direct path may still work, and the relay reconnects on
// its own.
func (c *Client) Send(dst key.Public, packet []byte) error {
	payload := make([]byte, keySize+len(packet))
	copy(payload, dst[:])
	copy(payload[keySize:], packet)
	return c.writeFrameLocked(frameSendPacket, payload)
}

// writeFrameLocked serialises writes onto the shared connection.
//
// Every writer — data path, keepalive — goes through here, because two
// concurrent Writes on one TCP connection would interleave and corrupt the
// framing.
func (c *Client) writeFrameLocked(t frameType, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return errors.New("relay: not connected")
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	return writeFrame(c.conn, t, payload)
}

// Recv returns the next relayed packet, blocking until one arrives.
func (c *Client) Recv(ctx context.Context) (Packet, error) {
	select {
	case p := <-c.recv:
		return p, nil
	case <-ctx.Done():
		return Packet{}, ctx.Err()
	case <-c.closed:
		return Packet{}, net.ErrClosed
	}
}

// Close ends the client permanently.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.mu.Lock()
		if c.conn != nil {
			c.conn.Close()
		}
		c.mu.Unlock()
	})
	return nil
}

func (c *Client) setConn(conn net.Conn) {
	c.mu.Lock()
	c.conn = conn
	was := c.connected
	c.connected = conn != nil
	changed := was != c.connected
	now := c.connected
	c.mu.Unlock()

	if changed && c.notify != nil {
		c.notify(now)
	}
}

// DialAddr turns a relay URL into a host:port to dial.
//
// Accepts a bare host, a host:port, or a URL, because an operator writing a
// config by hand should not have to remember which one this field wants.
func DialAddr(relayURL string) (string, error) {
	s := strings.TrimSpace(relayURL)
	if s == "" {
		return "", errors.New("relay: empty address")
	}

	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("parse relay URL %q: %w", relayURL, err)
		}
		host := u.Hostname()
		if host == "" {
			return "", fmt.Errorf("relay URL %q has no host", relayURL)
		}
		port := u.Port()
		if port == "" {
			port = strconv.Itoa(DefaultPort)
		}
		return net.JoinHostPort(host, port), nil
	}

	if host, port, err := net.SplitHostPort(s); err == nil {
		return net.JoinHostPort(host, port), nil
	}
	return net.JoinHostPort(s, strconv.Itoa(DefaultPort)), nil
}

// readFull is io.ReadFull without the import, kept local so the handshake
// reads the same way on both sides of the connection.
func readFull(conn net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := conn.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
