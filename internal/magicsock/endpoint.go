// Package magicsock is the socket that makes one UDP port behave like many
// paths.
//
// WireGuard wants a peer to have one endpoint: an address to send to. A mesh
// that survives NAT cannot offer it one, because the way to reach a peer
// changes — a relay at first, a LAN address once both ends notice they are on
// the same network, a hole-punched public address after that, and back to the
// relay when the laptop moves. Rebuilding the WireGuard configuration on every
// such change would tear down live sessions for what is only a routing
// decision.
//
// So the endpoint handed to WireGuard is not an address at all. It is the
// peer's node key, and this package decides — per packet, invisibly — which
// path that key currently resolves to. WireGuard sees one stable endpoint for
// the life of the peer and never learns that anything moved.
//
// That indirection is the whole reason the data plane runs wireguard-go in
// userspace rather than the kernel module: only a userspace device lets its
// socket be replaced with one that thinks like this.
package magicsock

import (
	"net/netip"
	"sync"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"golang.zx2c4.com/wireguard/conn"
)

// directTrust is how long a confirmed direct path is used without fresh
// evidence that it still works.
//
// The window has to outlast the quietest legitimate gap in inbound traffic.
// WireGuard's keepalive is 25 seconds, so a live peer is heard from at least
// that often even when idle; 45 seconds leaves room for one lost keepalive
// before the path is treated as unproven and the relay is brought back in
// alongside it. Once disco is running its heartbeat refreshes this far more
// often, and the timer stops mattering.
const directTrust = 45 * time.Second

// peerEndpoint is what WireGuard holds for a peer: an identity, not an address.
//
// It is a per-peer singleton. Every receive path — direct UDP, relay — returns
// this same pointer for a given node key, so WireGuard's roaming logic
// (SetEndpointFromPacket, which overwrites a peer's endpoint with whatever the
// last packet arrived on) sees no change and cannot undo our path selection.
type peerEndpoint struct {
	state *peerState
}

var _ conn.Endpoint = (*peerEndpoint)(nil)

// ClearSrc is a no-op: source addresses are this package's business, not
// WireGuard's, and there is nothing cached here for it to clear.
func (e *peerEndpoint) ClearSrc() {}

// SrcToString reports the path currently in use, purely so `wg show`-style
// output and the daemon's logs can say something true about where traffic is
// going.
func (e *peerEndpoint) SrcToString() string { return e.state.pathDescription() }

// DstToString must round-trip through ParseEndpoint, because wireguard-go
// prints it in UAPI output and reads it back on configuration. The node key is
// therefore the wire form of an endpoint throughout this package.
func (e *peerEndpoint) DstToString() string { return e.state.nodeKey.String() }

// DstToBytes feeds WireGuard's mac2 cookie calculation, which needs a stable,
// unique-per-peer byte string. The node key is exactly that.
func (e *peerEndpoint) DstToBytes() []byte {
	k := e.state.nodeKey
	return k[:]
}

// DstIP is used by WireGuard's under-load handshake rate limiter, which buckets
// by address. A peer with no address would put every peer in one bucket, so a
// single node flooding handshakes would throttle the whole mesh. Returning a
// stable synthetic address per node key keeps the buckets separate.
func (e *peerEndpoint) DstIP() netip.Addr { return e.state.syntheticIP }

// SrcIP has no meaning for an endpoint that is not an address.
func (e *peerEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// syntheticIPFor derives a stable address from a node key.
//
// It is never sent anywhere and never routed; it exists only to give
// WireGuard's rate limiter something to bucket on. The prefix is 100::/64, the
// RFC 6666 discard range, chosen so that a copy of one escaping into a log or a
// packet capture is unmistakably not a real destination.
func syntheticIPFor(k key.Public) netip.Addr {
	var b [16]byte
	b[0], b[1] = 0x01, 0x00 // 100::/64 discard prefix
	copy(b[8:], k[:8])
	return netip.AddrFrom16(b)
}

// peerState is everything known about how to reach one peer.
type peerState struct {
	nodeKey     key.Public
	syntheticIP netip.Addr
	ep          *peerEndpoint

	mu sync.Mutex

	// discoKey authenticates path probes to this peer. Zero until the control
	// plane has told us about it.
	discoKey key.Public

	// candidates are addresses the peer might be reachable at, newest netmap
	// wins. Unproven: any of them may be stale, firewalled, or another
	// network's idea of the same private address.
	candidates []netip.AddrPort

	// relayURL is the peer's home relay — where to reach it when no direct
	// path works. Empty means relay is not an option for this peer.
	relayURL string

	// best is the direct path currently in use, and bestAt when it last
	// carried something inbound. A path is only ever promoted by *receiving*
	// on it, never by sending: sending proves nothing about whether the other
	// end can hear us.
	best   netip.AddrPort
	bestAt time.Time

	// probes tracks in-flight disco pings by transaction ID, so a pong can be
	// matched to the address it validates and to the moment it was sent.
	probes map[[12]byte]*probe

	// lastProbeAt rate-limits probing, and lastRelayAt records when the relay
	// last carried traffic for this peer, both for diagnostics.
	lastProbeAt time.Time
	lastRelayAt time.Time

	// latency is the smoothed round-trip time of the direct path, or zero when
	// unmeasured.
	latency time.Duration

	// relayLatency is the same measurement for the relayed path.
	//
	// Kept separately rather than folded into latency because the two are
	// answers to different questions, and the gap between them is the entire
	// argument for hole punching. A relay in another country and a direct path
	// across the room are both "the peer is reachable"; only showing both makes
	// the difference visible.
	relayLatency time.Duration
}

// probe is one outstanding disco ping.
type probe struct {
	addr netip.AddrPort
	sent time.Time
}

func newPeerState(nodeKey key.Public) *peerState {
	ps := &peerState{
		nodeKey:     nodeKey,
		syntheticIP: syntheticIPFor(nodeKey),
		probes:      make(map[[12]byte]*probe),
	}
	ps.ep = &peerEndpoint{state: ps}
	return ps
}

// directPath returns the confirmed direct address, if one is still trusted.
func (ps *peerState) directPath() (netip.AddrPort, bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.directPathLocked()
}

func (ps *peerState) directPathLocked() (netip.AddrPort, bool) {
	if !ps.best.IsValid() {
		return netip.AddrPort{}, false
	}
	if time.Since(ps.bestAt) > directTrust {
		return netip.AddrPort{}, false
	}
	return ps.best, true
}

// noteDirectRecv records that a packet genuinely arrived from addr.
//
// This is the only thing that promotes a path, and it is deliberately the only
// thing: receipt is proof that the peer can reach us *and* that our reply has
// somewhere to go. An address we merely sent to has proven nothing.
func (ps *peerState) noteDirectRecv(addr netip.AddrPort) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	now := time.Now()
	if ps.best != addr {
		// Switching paths. Keep the old latency measurement out of it; the new
		// path will be measured on its own next probe.
		ps.best = addr
		ps.latency = 0
	}
	ps.bestAt = now
}

// pathDescription renders the current path for logs and status output.
func (ps *peerState) pathDescription() string {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if addr, ok := ps.directPathLocked(); ok {
		if ps.latency > 0 {
			return "direct " + addr.String() + " (" + ps.latency.Round(time.Millisecond).String() + ")"
		}
		return "direct " + addr.String()
	}
	if ps.relayURL != "" {
		return "relay " + ps.relayURL
	}
	return "no path"
}

// PeerStatus is a snapshot of one peer's connectivity, for `makima status`
// and `makima ping`.
type PeerStatus struct {
	NodeKey  key.Public
	Direct   netip.AddrPort
	DirectOK bool
	Latency  time.Duration

	RelayURL string

	// RelayLatency is the round-trip time through the relay, zero when
	// unmeasured. Reported alongside Latency rather than instead of it: the
	// gap between the two is what a direct path is worth.
	RelayLatency time.Duration

	Candidates []netip.AddrPort
	LastRelay  time.Time
}

func (ps *peerState) status() PeerStatus {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	addr, ok := ps.directPathLocked()
	return PeerStatus{
		NodeKey:      ps.nodeKey,
		Direct:       addr,
		DirectOK:     ok,
		Latency:      ps.latency,
		RelayURL:     ps.relayURL,
		RelayLatency: ps.relayLatency,
		Candidates:   append([]netip.AddrPort(nil), ps.candidates...),
		LastRelay:    ps.lastRelayAt,
	}
}
