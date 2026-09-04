package magicsock

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/justin06lee/makima/internal/disco"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/relay"
	"github.com/justin06lee/makima/internal/stun"
	"github.com/justin06lee/makima/internal/wg"
	"golang.zx2c4.com/wireguard/conn"
)

// Options configure a Conn.
type Options struct {
	// Port is the UDP port to bind. Zero asks the OS to choose, which is fine
	// once endpoints are discovered and published rather than assumed.
	Port uint16

	// NodeKey is this node's WireGuard identity. The relay routes by its
	// public half.
	NodeKey key.Private

	// DiscoKey authenticates path probes. Separate from NodeKey so probing can
	// happen before any WireGuard session exists, and so a probe cannot be
	// replayed into the data path.
	DiscoKey key.Private

	Logger *log.Logger
}

// Conn is the socket WireGuard is given instead of a plain UDP one.
//
// It owns exactly one UDP port and one optional relay connection, and it
// multiplexes every peer over both. Nothing above it — not WireGuard, not the
// daemon — has to know which of the two a given packet took.
type Conn struct {
	log      *log.Logger
	nodeKey  key.Private
	discoKey key.Private

	mu    sync.RWMutex
	pconn *net.UDPConn
	port  uint16

	peers   map[key.Public]*peerState // by node key
	byDisco map[key.Public]*peerState // by disco key, for probe attribution
	byAddr  map[netip.AddrPort]*peerState

	// relayClient is the current home-relay connection, replaced when the
	// control plane reassigns us. nil when no relay is configured.
	relayClient *relay.Client
	relayCancel context.CancelFunc
	relayURL    string

	// relayIn carries inbound relayed packets from whichever client is
	// current. Keeping it on the Conn rather than the client means a relay
	// swap does not disturb the receive path WireGuard is parked on.
	relayIn chan relay.Packet

	// selfMu guards the observed-address set, which is written by the probe
	// path and read by endpoint advertisement. It is deliberately not the main
	// lock: an observation arriving must never contend with the packet path.
	selfMu   sync.Mutex
	observed []selfObservation

	// stunTx tracks outstanding STUN binding transactions. Separate from the
	// main lock for the same reason as selfMu: a reply arriving must not
	// contend with the packet path.
	stunMu sync.Mutex
	stunTx map[stun.TxID]time.Time

	// pairing is the open serverless pairing window, nil when closed, and
	// knocks are the pairings this node has started and is awaiting an answer
	// to. Both are guarded by pairMu, which is again separate from the main
	// lock: a knock arriving must not contend with the packet path, and
	// accepting one calls out into the daemon.
	pairMu  sync.Mutex
	pairing *Pairing
	knocks  map[disco.TxID]*pending

	// derived from Options, kept for probing
	ctx       context.Context
	ctxCancel context.CancelFunc

	closeOnce sync.Once
	closed    chan struct{}
}

var _ conn.Bind = (*Conn)(nil)

// New binds the UDP socket and returns a Conn ready to be handed to WireGuard.
//
// The socket is opened here rather than in Open because the port must be known
// before WireGuard exists: the node has to tell the control plane which port
// its endpoints advertise, and that happens during registration, well before
// the tunnel comes up.
func New(opts Options) (*Conn, error) {
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}

	c := &Conn{
		log:      opts.Logger,
		nodeKey:  opts.NodeKey,
		discoKey: opts.DiscoKey,
		peers:    make(map[key.Public]*peerState),
		byDisco:  make(map[key.Public]*peerState),
		byAddr:   make(map[netip.AddrPort]*peerState),
		relayIn:  make(chan relay.Packet, 256),
		stunTx:   make(map[stun.TxID]time.Time),
		closed:   make(chan struct{}),
	}
	c.ctx, c.ctxCancel = context.WithCancel(context.Background())

	if err := c.bind(opts.Port); err != nil {
		return nil, err
	}
	go c.probeLoop()
	return c, nil
}

// bind opens the UDP socket.
//
// "udp" rather than "udp4" so one socket serves both families: v4-mapped
// addresses arrive on it, and an IPv6-only network still has a path. Peers are
// still advertised as IPv4 for now, but the socket does not need to care.
func (c *Conn) bind(port uint16) error {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return fmt.Errorf("bind udp port %d: %w", port, err)
	}

	actual := uint16(pc.LocalAddr().(*net.UDPAddr).Port)

	c.mu.Lock()
	old := c.pconn
	c.pconn = pc
	c.port = actual
	c.mu.Unlock()

	if old != nil {
		old.Close()
	}
	return nil
}

// LocalPort is the UDP port in use, which is what endpoint advertisement needs.
func (c *Conn) LocalPort() uint16 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.port
}

// DiscoPublicKey is this node's disco identity, published through the netmap
// so peers can authenticate our probes.
func (c *Conn) DiscoPublicKey() key.Public { return c.discoKey.Public() }

// --- conn.Bind ---------------------------------------------------------

// Open reports the receive functions WireGuard should run.
//
// The socket already exists, so a requested port only causes a rebind when it
// actually differs. WireGuard calls this on start and on any listen_port
// change.
func (c *Conn) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	select {
	case <-c.closed:
		return nil, 0, net.ErrClosed
	default:
	}

	if port != 0 && port != c.LocalPort() {
		if err := c.bind(port); err != nil {
			return nil, 0, err
		}
	}
	return []conn.ReceiveFunc{c.receiveUDP, c.receiveRelay}, c.LocalPort(), nil
}

// Close tears down the socket and the relay connection.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.ctxCancel()

		c.mu.Lock()
		pconn := c.pconn
		rc := c.relayClient
		cancel := c.relayCancel
		c.pconn = nil
		c.relayClient = nil
		c.relayCancel = nil
		c.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		if rc != nil {
			rc.Close()
		}
		if pconn != nil {
			pconn.Close()
		}
	})
	return nil
}

// SetMark is a Linux traffic-marking hook makima does not use. Returning nil
// rather than an error because WireGuard calls it unconditionally.
func (c *Conn) SetMark(uint32) error { return nil }

// BatchSize is one.
//
// StdNetBind reads up to 128 datagrams per syscall on Linux, which is a real
// throughput win. It is not available here: every packet needs individual
// demultiplexing — is this disco or data, which peer, which path — and a batch
// can legitimately contain packets for several peers, which the ReceiveFunc
// contract has no way to express. Correct path selection is worth more than
// syscall amortisation on a link whose ceiling is the internet.
func (c *Conn) BatchSize() int { return 1 }

// ParseEndpoint turns the wire form — a node key — back into an endpoint.
//
// WireGuard calls this when the daemon configures a peer, with whatever string
// the config carried. Since DstToString emits the node key, this is the exact
// inverse, and a peer's endpoint round-trips through UAPI unchanged.
func (c *Conn) ParseEndpoint(s string) (conn.Endpoint, error) {
	k, err := key.ParsePublic(s)
	if err != nil {
		return nil, fmt.Errorf("magicsock: endpoint %q is not a node key: %w", s, err)
	}
	return c.peerFor(k).ep, nil
}

// EndpointString renders a peer's WireGuard endpoint as its node key.
//
// Pair it with a Conn as wg.Options.Endpoint. Every peer gets an endpoint
// unconditionally — even one with no known address — because the endpoint no
// longer means "where this peer is". It means "which peer this is", and the
// answer is always known.
func EndpointString(p wg.Peer) string { return p.PublicKey.String() }

// peerFor returns the state for a node key, creating it if this is the first
// time we have heard of it.
func (c *Conn) peerFor(k key.Public) *peerState {
	c.mu.RLock()
	ps, ok := c.peers[k]
	c.mu.RUnlock()
	if ok {
		return ps
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if ps, ok := c.peers[k]; ok {
		return ps
	}
	ps = newPeerState(k)
	c.peers[k] = ps
	return ps
}

// --- receive -----------------------------------------------------------

// receiveUDP reads one datagram from the wire and attributes it to a peer.
//
// Disco packets are consumed here and never surface: they are this package's
// own control traffic, and WireGuard would reject them as malformed.
func (c *Conn) receiveUDP(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	for {
		c.mu.RLock()
		pc := c.pconn
		c.mu.RUnlock()

		if pc == nil {
			return 0, net.ErrClosed
		}

		n, src, err := pc.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			select {
			case <-c.closed:
				return 0, net.ErrClosed
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return 0, net.ErrClosed
			}
			// A transient read error — an ICMP port-unreachable surfacing as
			// ECONNREFUSED, most often — must not kill the receive loop, or one
			// unreachable peer takes the whole tunnel down.
			continue
		}
		if n == 0 {
			continue
		}

		src = normalise(src)
		b := packets[0][:n]

		// Three protocols share this socket, and each is classified before the
		// next is tried. Disco carries an unmistakable ASCII prefix; STUN a
		// fixed magic cookie at a fixed offset; anything else is WireGuard's.
		// The order matters only in that the two cheap checks come first.
		if isDiscoPacket(b) {
			c.handleDisco(b, src)
			continue
		}
		if stun.Is(b) {
			c.handleSTUN(b)
			continue
		}

		ps := c.peerForAddr(src)
		if ps == nil {
			// A packet from an address no peer has claimed. Before disco has
			// run this is normal for a peer whose endpoint we were never told
			// about; there is no way to attribute it, so it is dropped and the
			// relay carries the session until probing succeeds.
			continue
		}

		ps.noteDirectRecv(src)
		sizes[0] = n
		eps[0] = ps.ep
		return 1, nil
	}
}

// receiveRelay delivers packets that arrived over the relay.
//
// Attribution is free here: the relay's frame header names the sender, and
// only a connection that proved possession of that node key could have set it.
func (c *Conn) receiveRelay(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	for {
		select {
		case <-c.closed:
			return 0, net.ErrClosed

		case p := <-c.relayIn:
			if isDiscoPacket(p.Data) {
				c.handleDiscoRelayed(p.Data, p.Src)
				continue
			}

			c.mu.RLock()
			ps, ok := c.peers[p.Src]
			c.mu.RUnlock()
			if !ok {
				continue
			}

			n := copy(packets[0], p.Data)
			if n < len(p.Data) {
				// The relay's frame limit is well above the tunnel MTU, so
				// this means a misconfiguration rather than a normal jumbo.
				c.log.Printf("magicsock: relayed packet from %s truncated (%d > %d)", shortKey(p.Src), len(p.Data), len(packets[0]))
				continue
			}

			ps.mu.Lock()
			ps.lastRelayAt = time.Now()
			ps.mu.Unlock()

			sizes[0] = n
			eps[0] = ps.ep
			return 1, nil
		}
	}
}

// peerForAddr resolves a source address to a peer.
func (c *Conn) peerForAddr(addr netip.AddrPort) *peerState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byAddr[addr]
}

// --- send --------------------------------------------------------------

// errNoPath reports that a peer is currently unreachable by any route.
var errNoPath = errors.New("magicsock: no path to peer")

// Send delivers packets to a peer over whichever path is currently best.
//
// With a confirmed direct path it sends there and nowhere else. Without one it
// sends to every candidate address *and* the relay at once. That duplication is
// deliberate and cheap: it is bounded by the candidate count, it only happens
// while a peer is unproven, and it means a session starts on whichever path
// works rather than waiting for probing to finish deciding.
func (c *Conn) Send(bufs [][]byte, ep conn.Endpoint) error {
	pe, ok := ep.(*peerEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	ps := pe.state

	if addr, ok := ps.directPath(); ok {
		return c.sendUDP(bufs, addr)
	}

	ps.mu.Lock()
	candidates := append([]netip.AddrPort(nil), ps.candidates...)
	if ps.best.IsValid() {
		// A path that has gone quiet is still the best guess we have; keep
		// trying it alongside the rest rather than abandoning it outright.
		candidates = appendUnique(candidates, ps.best)
	}
	hasRelay := ps.relayURL != ""
	ps.mu.Unlock()

	var sent bool
	for _, addr := range candidates {
		if err := c.sendUDP(bufs, addr); err == nil {
			sent = true
		}
	}

	if hasRelay {
		if err := c.sendRelay(bufs, ps.nodeKey); err == nil {
			sent = true
			ps.mu.Lock()
			ps.lastRelayAt = time.Now()
			ps.mu.Unlock()
		}
	}

	// An unreachable peer is worth probing sooner rather than on the next
	// tick, since this is the moment we learned someone wants to talk to it.
	c.maybeProbe(ps)

	if !sent {
		return errNoPath
	}
	return nil
}

func (c *Conn) sendUDP(bufs [][]byte, addr netip.AddrPort) error {
	c.mu.RLock()
	pc := c.pconn
	c.mu.RUnlock()
	if pc == nil {
		return net.ErrClosed
	}

	var firstErr error
	for _, b := range bufs {
		if _, err := pc.WriteToUDPAddrPort(b, addr); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *Conn) sendRelay(bufs [][]byte, dst key.Public) error {
	c.mu.RLock()
	rc := c.relayClient
	c.mu.RUnlock()
	if rc == nil {
		return errNoPath
	}

	var firstErr error
	for _, b := range bufs {
		if err := rc.Send(dst, b); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// --- network configuration --------------------------------------------

// PeerConfig is what the control plane knows about how to reach one peer.
type PeerConfig struct {
	NodeKey   key.Public
	DiscoKey  key.Public
	Endpoints []netip.AddrPort
	RelayURL  string
}

// SetNetwork applies a netmap's view of the mesh.
//
// Called on every netmap update. Peers not in the list are forgotten, so a
// node evicted from the mesh stops being a valid source address immediately
// rather than lingering until something else notices.
func (c *Conn) SetNetwork(peers []PeerConfig, homeRelay string, relayKey key.Public) {
	c.mu.Lock()

	keep := make(map[key.Public]bool, len(peers))
	byAddr := make(map[netip.AddrPort]*peerState, len(peers)*2)
	byDisco := make(map[key.Public]*peerState, len(peers))

	for _, p := range peers {
		keep[p.NodeKey] = true

		ps, ok := c.peers[p.NodeKey]
		if !ok {
			ps = newPeerState(p.NodeKey)
			c.peers[p.NodeKey] = ps
		}

		ps.mu.Lock()
		ps.discoKey = p.DiscoKey
		ps.candidates = append([]netip.AddrPort(nil), p.Endpoints...)
		ps.relayURL = p.RelayURL
		// A confirmed path that is no longer advertised stays confirmed: we
		// have direct evidence it works, which outranks the control plane's
		// second-hand list.
		best := ps.best
		ps.mu.Unlock()

		for _, e := range p.Endpoints {
			byAddr[normalise(e)] = ps
		}
		if best.IsValid() {
			byAddr[normalise(best)] = ps
		}
		if !p.DiscoKey.IsZero() {
			byDisco[p.DiscoKey] = ps
		}
	}

	for k := range c.peers {
		if !keep[k] {
			delete(c.peers, k)
		}
	}
	c.byAddr = byAddr
	c.byDisco = byDisco
	c.mu.Unlock()

	c.setRelay(homeRelay, relayKey)
}

// setRelay reconciles the home-relay connection with the netmap's assignment.
func (c *Conn) setRelay(url string, relayKey key.Public) {
	c.mu.Lock()
	if url == c.relayURL {
		c.mu.Unlock()
		return
	}

	oldClient := c.relayClient
	oldCancel := c.relayCancel
	c.relayURL = url
	c.relayClient = nil
	c.relayCancel = nil

	var (
		newClient *relay.Client
		newCancel context.CancelFunc
		ctx       context.Context
	)
	if url != "" {
		ctx, newCancel = context.WithCancel(c.ctx)
		newClient = relay.NewClient(url, relayKey, c.nodeKey)
		newClient.SetLogger(c.log)
		newClient.OnStateChange(func(up bool) {
			if up {
				c.log.Printf("relay %s connected", url)
			} else {
				c.log.Printf("relay %s disconnected", url)
			}
		})
		c.relayClient = newClient
		c.relayCancel = newCancel
	}
	c.mu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	if oldClient != nil {
		oldClient.Close()
	}

	if newClient != nil {
		go newClient.Run(ctx)
		go c.pumpRelay(ctx, newClient)
	}
}

// pumpRelay moves packets from one relay client into the shared inbound
// channel, so the receive path is not disturbed when the client is replaced.
func (c *Conn) pumpRelay(ctx context.Context, rc *relay.Client) {
	for {
		p, err := rc.Recv(ctx)
		if err != nil {
			return
		}
		select {
		case c.relayIn <- p:
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		default:
			// WireGuard is not draining. Dropping matches what the network
			// would do to an over-buffered path anyway.
		}
	}
}

// RelayConnected reports whether the home relay currently has a session.
func (c *Conn) RelayConnected() bool {
	c.mu.RLock()
	rc := c.relayClient
	c.mu.RUnlock()
	return rc != nil && rc.Connected()
}

// RelayURL is the home relay in use, empty when none is assigned.
func (c *Conn) RelayURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.relayURL
}

// Status snapshots every peer's connectivity.
func (c *Conn) Status() []PeerStatus {
	c.mu.RLock()
	states := make([]*peerState, 0, len(c.peers))
	for _, ps := range c.peers {
		states = append(states, ps)
	}
	c.mu.RUnlock()

	out := make([]PeerStatus, 0, len(states))
	for _, ps := range states {
		out = append(out, ps.status())
	}
	return out
}

// normalise collapses a v4-mapped IPv6 address to plain IPv4.
//
// A dual-stack socket reports an IPv4 sender as ::ffff:a.b.c.d, while the
// control plane advertises the same host as a.b.c.d. Without this the two
// never compare equal and a perfectly good direct path is never recognised.
func normalise(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

func appendUnique(s []netip.AddrPort, a netip.AddrPort) []netip.AddrPort {
	for _, x := range s {
		if x == a {
			return s
		}
	}
	return append(s, a)
}

func shortKey(k key.Public) string {
	s := k.String()
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
