package relay

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// sendQueue is how many frames may be buffered for a slow client.
//
// The number is a deliberate compromise. Too small and a brief scheduling
// hiccup drops packets that WireGuard would then have to retransmit; too large
// and a client that has stopped reading becomes a memory leak with a routing
// table entry. 128 frames is roughly a tenth of a second of a busy flow, which
// is long enough to ride out a stall and short enough that a dead client is
// noticed rather than accumulated.
const sendQueue = 128

// writeTimeout bounds a single frame write. A client whose TCP window has been
// closed for this long is not coming back fast enough to matter, and holding
// the forwarding goroutine on it would let one stalled peer degrade the relay
// for everyone.
const writeTimeout = 10 * time.Second

// handshakeTimeout bounds the setup exchange, so a connection that opens and
// says nothing cannot occupy a slot indefinitely.
const handshakeTimeout = 10 * time.Second

// Server forwards packets between connected nodes.
type Server struct {
	privateKey key.Private
	log        *log.Logger

	mu      sync.RWMutex
	clients map[key.Public]*serverClient

	// Counters for the status endpoint. Atomic rather than mutex-guarded
	// because they are touched on every forwarded packet, and the routing
	// table's lock is already the hot one.
	stats Stats
}

// Stats is a relay's lifetime activity.
type Stats struct {
	Accepted  atomic.Uint64 // connections that completed the handshake
	Rejected  atomic.Uint64 // connections that failed it
	Forwarded atomic.Uint64 // frames delivered to a connected destination
	Dropped   atomic.Uint64 // frames discarded: unknown or backed-up destination
}

// serverClient is one connected node.
type serverClient struct {
	nodeKey key.Public
	conn    net.Conn
	send    chan []byte

	// closeOnce guards teardown, which can be triggered by the read loop, the
	// write loop, or the server shutting down, all concurrently.
	closeOnce sync.Once
	closed    chan struct{}
}

// NewServer builds a relay with the given identity.
func NewServer(privateKey key.Private, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		privateKey: privateKey,
		log:        logger,
		clients:    make(map[key.Public]*serverClient),
	}
}

// PublicKey is the relay's identity, which nodes seal their handshake to.
func (s *Server) PublicKey() key.Public { return s.privateKey.Public() }

// Stats reports lifetime counters.
func (s *Server) Stats() *Stats { return &s.stats }

// ConnectedCount is how many nodes currently hold a connection.
func (s *Server) ConnectedCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// Connected reports every node key currently reachable through this relay.
func (s *Server) Connected() []key.Public {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]key.Public, 0, len(s.clients))
	for k := range s.clients {
		out = append(out, k)
	}
	return out
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

// Close disconnects every client. The listener is the caller's to close.
func (s *Server) Close() {
	s.mu.Lock()
	clients := make([]*serverClient, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, c)
	}
	s.clients = make(map[key.Public]*serverClient)
	s.mu.Unlock()

	for _, c := range clients {
		c.close()
	}
}

// handle runs one connection through the handshake and then forwards for it.
func (s *Server) handle(rawConn net.Conn) {
	defer rawConn.Close()

	// Nagle would coalesce small frames and add latency to exactly the traffic
	// that cares about it most: a relay carries interactive flows that a
	// direct path could not.
	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	nodeKey, err := s.handshake(rawConn)
	if err != nil {
		s.stats.Rejected.Add(1)
		// Logged at low volume and without the remote address's port, since a
		// public relay attracts a steady background of scanners.
		s.log.Printf("relay: handshake from %s failed: %v", hostOf(rawConn.RemoteAddr()), err)
		return
	}

	c := &serverClient{
		nodeKey: nodeKey,
		conn:    rawConn,
		send:    make(chan []byte, sendQueue),
		closed:  make(chan struct{}),
	}

	// A node that reconnects — a laptop that changed networks, say — must
	// displace its old connection rather than sit beside it, or forwarding
	// would race between a live socket and a dead one.
	s.mu.Lock()
	if old, ok := s.clients[nodeKey]; ok {
		delete(s.clients, nodeKey)
		s.mu.Unlock()
		old.close()
		s.mu.Lock()
	}
	s.clients[nodeKey] = c
	s.mu.Unlock()

	s.stats.Accepted.Add(1)
	s.log.Printf("relay: %s connected (%d node(s) online)", shortKey(nodeKey), s.ConnectedCount())

	defer func() {
		s.mu.Lock()
		// Only remove ourselves: a reconnect may already have replaced this
		// entry, and deleting unconditionally would evict the live connection.
		if cur, ok := s.clients[nodeKey]; ok && cur == c {
			delete(s.clients, nodeKey)
		}
		s.mu.Unlock()
		c.close()
		s.log.Printf("relay: %s disconnected (%d node(s) online)", shortKey(nodeKey), s.ConnectedCount())
	}()

	go c.writeLoop()
	s.readLoop(c)
}

// handshake authenticates a connection and returns the node key it proved.
func (s *Server) handshake(c net.Conn) (key.Public, error) {
	if err := c.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return key.Public{}, err
	}
	// Clear the deadline afterwards: a relayed connection is legitimately idle
	// for long stretches, and an inherited deadline would kill it mid-session.
	defer c.SetDeadline(time.Time{})

	if _, err := c.Write(magic[:]); err != nil {
		return key.Public{}, err
	}

	var challenge [challengeSize]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return key.Public{}, err
	}

	hello, err := json.Marshal(serverHello{
		Version:   ProtocolVersion,
		RelayKey:  s.privateKey.Public(),
		Challenge: challenge[:],
	})
	if err != nil {
		return key.Public{}, err
	}
	if err := writeFrame(c, frameServerHello, hello); err != nil {
		return key.Public{}, err
	}

	buf := make([]byte, maxFrameSize)
	t, payload, err := readFrame(c, buf)
	if err != nil {
		return key.Public{}, err
	}
	if t != frameClientHello {
		return key.Public{}, errors.New("expected a client hello")
	}

	var ch clientHello
	if err := json.Unmarshal(payload, &ch); err != nil {
		return key.Public{}, err
	}
	if ch.Version != ProtocolVersion {
		return key.Public{}, errors.New("protocol version mismatch")
	}
	if ch.NodeKey.IsZero() {
		return key.Public{}, errors.New("empty node key")
	}

	// The proof: only the holder of this node key's private half could have
	// sealed our challenge to us. Anything else fails to open.
	plain, err := key.Open(ch.Sealed, ch.Nonce, ch.NodeKey, s.privateKey)
	if err != nil {
		return key.Public{}, err
	}
	if len(plain) != challengeSize || string(plain) != string(challenge[:]) {
		return key.Public{}, errors.New("challenge response did not match")
	}
	return ch.NodeKey, nil
}

// readLoop forwards this client's frames until the connection ends.
func (s *Server) readLoop(c *serverClient) {
	buf := make([]byte, maxFrameSize)

	for {
		t, payload, err := readFrame(c.conn, buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.log.Printf("relay: read from %s: %v", shortKey(c.nodeKey), err)
			}
			return
		}

		switch t {
		case frameSendPacket:
			if len(payload) < keySize {
				s.log.Printf("relay: %s sent a packet with no destination", shortKey(c.nodeKey))
				return
			}
			var dst key.Public
			copy(dst[:], payload[:keySize])
			s.forward(c.nodeKey, dst, payload[keySize:])

		case framePing:
			// Echo. The relay is the client's only evidence the path is alive
			// while no traffic is flowing.
			if !c.enqueue(frame(framePong, payload)) {
				return
			}

		default:
			// An unknown frame from a peer that completed the handshake is a
			// version skew, not an attack. Ignore it rather than dropping a
			// working connection over a frame we do not need.
		}
	}
}

// forward copies one packet to its destination, rewriting the routing header
// from "who this is for" to "who this is from".
//
// The relay never inspects past that header. What follows is a WireGuard
// packet it holds no key for, which is the property that makes running one
// safe for a stranger.
func (s *Server) forward(from, to key.Public, packet []byte) {
	s.mu.RLock()
	dst, ok := s.clients[to]
	s.mu.RUnlock()

	if !ok {
		// Routine: the destination may simply not be online, and the sender
		// will fall back or retry. Silence here is deliberate — logging every
		// such packet would let one misconfigured node flood the log.
		s.stats.Dropped.Add(1)
		return
	}

	out := make([]byte, keySize+len(packet))
	copy(out, from[:])
	copy(out[keySize:], packet)

	if dst.enqueue(frame(frameRecvPacket, out)) {
		s.stats.Forwarded.Add(1)
	} else {
		s.stats.Dropped.Add(1)
	}
}

// frame renders a complete frame into a fresh buffer.
//
// The write loop cannot borrow the read loop's buffer — the two run
// concurrently and the read loop reuses its own on the next iteration — so a
// forwarded packet is copied exactly once, here.
func frame(t frameType, payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = byte(t)
	b[1] = byte(len(payload) >> 24)
	b[2] = byte(len(payload) >> 16)
	b[3] = byte(len(payload) >> 8)
	b[4] = byte(len(payload))
	copy(b[5:], payload)
	return b
}

// enqueue hands a frame to the write loop, reporting false if the client is
// too far behind to accept it.
//
// Dropping rather than blocking is the whole design. A relay that waits on a
// slow client stops forwarding for everyone else, which converts one bad
// connection into an outage. WireGuard treats the underlying transport as
// lossy anyway, so a dropped frame is a retransmit rather than a failure.
func (c *serverClient) enqueue(b []byte) bool {
	select {
	case c.send <- b:
		return true
	case <-c.closed:
		return false
	default:
		return false
	}
}

func (c *serverClient) writeLoop() {
	for {
		select {
		case b := <-c.send:
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				c.close()
				return
			}
			if _, err := c.conn.Write(b); err != nil {
				c.close()
				return
			}
		case <-c.closed:
			return
		}
	}
}

func (c *serverClient) close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.conn.Close()
	})
}

// shortKey renders a key briefly enough to read in a log line while staying
// long enough to tell nodes apart.
func shortKey(k key.Public) string {
	s := k.String()
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func hostOf(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
