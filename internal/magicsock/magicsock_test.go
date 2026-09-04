package magicsock

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/relay"
	"golang.zx2c4.com/wireguard/conn"
)

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func newConn(t *testing.T) (*Conn, key.Private, key.Private) {
	t.Helper()

	nodeKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	discoKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	c, err := New(Options{NodeKey: nodeKey, DiscoKey: discoKey, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, nodeKey, discoKey
}

// testRelay starts a relay for the integration tests below.
func testRelay(t *testing.T) (string, key.Public) {
	t.Helper()

	priv, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	srv := relay.NewServer(priv, quietLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() {
		ln.Close()
		srv.Close()
	})
	return ln.Addr().String(), priv.Public()
}

// The central claim of this package: WireGuard's endpoint for a peer is the
// peer's identity, and it survives every path change because it never
// described a path in the first place.
func TestEndpointIsTheNodeKey(t *testing.T) {
	c, _, _ := newConn(t)

	peerKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	pub := peerKey.Public()

	ep, err := c.ParseEndpoint(pub.String())
	if err != nil {
		t.Fatal(err)
	}
	if ep.DstToString() != pub.String() {
		t.Errorf("endpoint renders as %q, want the node key %q", ep.DstToString(), pub)
	}

	// It must round-trip, because wireguard-go prints it in UAPI output and
	// reads it back on the next configuration.
	again, err := c.ParseEndpoint(ep.DstToString())
	if err != nil {
		t.Fatal(err)
	}
	if again != ep {
		t.Error("re-parsing an endpoint produced a different object; WireGuard's peer identity would not be stable")
	}
}

// Every receive path must yield the same endpoint pointer for a peer, or
// WireGuard's roaming logic would overwrite our path selection.
func TestEndpointIsAPerPeerSingleton(t *testing.T) {
	c, _, _ := newConn(t)

	peerKey, _ := key.NewPrivate()
	pub := peerKey.Public()

	a := c.peerFor(pub).ep
	b := c.peerFor(pub).ep
	if a != b {
		t.Error("two lookups produced different endpoints for one peer")
	}
}

func TestParseEndpointRejectsAnAddress(t *testing.T) {
	c, _, _ := newConn(t)
	if _, err := c.ParseEndpoint("192.0.2.1:51820"); err == nil {
		t.Error("an address was accepted as an endpoint; it must be a node key")
	}
}

// The rate limiter buckets on DstIP, so peers must not collide there.
func TestSyntheticIPsAreDistinct(t *testing.T) {
	seen := make(map[netip.Addr]bool)
	for i := 0; i < 64; i++ {
		k, _ := key.NewPrivate()
		ip := syntheticIPFor(k.Public())
		if seen[ip] {
			t.Fatal("two node keys produced the same synthetic address")
		}
		seen[ip] = true
	}
}

// A path is only ever promoted by receiving on it. Sending proves nothing
// about whether the far end can hear us.
func TestOnlyReceiptPromotesAPath(t *testing.T) {
	ps := newPeerState(key.Public{1})
	addr := netip.MustParseAddrPort("192.0.2.10:51820")

	if _, ok := ps.directPath(); ok {
		t.Fatal("a fresh peer already had a direct path")
	}

	ps.noteDirectRecv(addr)
	got, ok := ps.directPath()
	if !ok || got != addr {
		t.Errorf("after receiving from %s the path is %s (ok=%v)", addr, got, ok)
	}
}

// Trust in a direct path has to lapse, or a silently-broken path would be used
// forever.
func TestDirectPathTrustExpires(t *testing.T) {
	ps := newPeerState(key.Public{1})
	ps.noteDirectRecv(netip.MustParseAddrPort("192.0.2.10:51820"))

	ps.mu.Lock()
	ps.bestAt = time.Now().Add(-directTrust - time.Second)
	ps.mu.Unlock()

	if _, ok := ps.directPath(); ok {
		t.Error("a path with no recent inbound traffic is still trusted")
	}
}

// Switching paths must discard the old latency, or the new path is judged by
// the old one's measurement.
func TestPathSwitchClearsLatency(t *testing.T) {
	ps := newPeerState(key.Public{1})

	ps.noteDirectRecv(netip.MustParseAddrPort("192.0.2.10:51820"))
	ps.mu.Lock()
	ps.latency = 50 * time.Millisecond
	ps.mu.Unlock()

	ps.noteDirectRecv(netip.MustParseAddrPort("192.0.2.11:51820"))

	ps.mu.Lock()
	got := ps.latency
	ps.mu.Unlock()
	if got != 0 {
		t.Errorf("latency after a path switch is %s, want zero", got)
	}
}

// A dual-stack socket reports IPv4 senders as v4-mapped. Without normalising,
// a perfectly good direct path never compares equal to the advertised one.
func TestNormaliseUnmapsV4(t *testing.T) {
	mapped := netip.MustParseAddrPort("[::ffff:192.0.2.1]:51820")
	plain := netip.MustParseAddrPort("192.0.2.1:51820")

	if normalise(mapped) != plain {
		t.Errorf("normalise(%s) = %s, want %s", mapped, normalise(mapped), plain)
	}
}

// A peer dropped from the netmap must stop being a valid source address at
// once, rather than lingering until something else notices.
func TestForgottenPeerIsRemoved(t *testing.T) {
	c, _, _ := newConn(t)

	a, _ := key.NewPrivate()
	b, _ := key.NewPrivate()
	addr := netip.MustParseAddrPort("192.0.2.10:51820")

	c.SetNetwork([]PeerConfig{
		{NodeKey: a.Public(), Endpoints: []netip.AddrPort{addr}},
		{NodeKey: b.Public()},
	}, "", key.Public{})

	if c.peerForAddr(addr) == nil {
		t.Fatal("an advertised endpoint was not registered")
	}

	c.SetNetwork([]PeerConfig{{NodeKey: b.Public()}}, "", key.Public{})

	if c.peerForAddr(addr) != nil {
		t.Error("a forgotten peer's address is still attributed to it")
	}
	c.mu.RLock()
	_, stillThere := c.peers[a.Public()]
	c.mu.RUnlock()
	if stillThere {
		t.Error("a forgotten peer is still in the peer table")
	}
}

// A confirmed path outranks the control plane's second-hand list: we have
// direct evidence it works.
func TestConfirmedPathSurvivesANetmapThatOmitsIt(t *testing.T) {
	c, _, _ := newConn(t)

	peer, _ := key.NewPrivate()
	addr := netip.MustParseAddrPort("192.0.2.10:51820")

	c.SetNetwork([]PeerConfig{{NodeKey: peer.Public(), Endpoints: []netip.AddrPort{addr}}}, "", key.Public{})
	c.peerFor(peer.Public()).noteDirectRecv(addr)

	// A new netmap that no longer advertises the address.
	c.SetNetwork([]PeerConfig{{NodeKey: peer.Public()}}, "", key.Public{})

	if c.peerForAddr(addr) == nil {
		t.Error("a proven path was forgotten because the netmap stopped advertising it")
	}
}

func TestSendToUnreachablePeerFails(t *testing.T) {
	c, _, _ := newConn(t)

	peer, _ := key.NewPrivate()
	ep, err := c.ParseEndpoint(peer.Public().String())
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Send([][]byte{{1, 2, 3}}, ep); err == nil {
		t.Error("sending to a peer with no candidates and no relay reported success")
	}
}

func TestSendRejectsAForeignEndpoint(t *testing.T) {
	c, _, _ := newConn(t)
	if err := c.Send([][]byte{{1}}, &foreignEndpoint{}); err != conn.ErrWrongEndpointType {
		t.Errorf("got %v, want ErrWrongEndpointType", err)
	}
}

type foreignEndpoint struct{}

func (foreignEndpoint) ClearSrc()           {}
func (foreignEndpoint) SrcToString() string { return "" }
func (foreignEndpoint) DstToString() string { return "" }
func (foreignEndpoint) DstToBytes() []byte  { return nil }
func (foreignEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (foreignEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// The whole of M2 in one test: two nodes with no route to each other exchange
// a packet through a relay, and the receiver attributes it to the right peer.
func TestRelayCarriesPacketsBetweenPeers(t *testing.T) {
	relayAddr, relayKey := testRelay(t)

	a, aNode, aDisco := newConn(t)
	b, bNode, bDisco := newConn(t)

	// Each knows the other only by key and relay — no addresses at all, which
	// is exactly the situation two NATed machines are in.
	a.SetNetwork([]PeerConfig{{
		NodeKey: bNode.Public(), DiscoKey: bDisco.Public(), RelayURL: relayAddr,
	}}, relayAddr, relayKey)

	b.SetNetwork([]PeerConfig{{
		NodeKey: aNode.Public(), DiscoKey: aDisco.Public(), RelayURL: relayAddr,
	}}, relayAddr, relayKey)

	waitRelay(t, a)
	waitRelay(t, b)

	// Take B's receive functions the way WireGuard would.
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fns) != 2 {
		t.Fatalf("Open returned %d receive functions, want 2", len(fns))
	}
	recvRelay := fns[1]

	payload := []byte("a wireguard handshake initiation, as far as anyone here knows")

	ep, err := a.ParseEndpoint(bNode.Public().String())
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		ep  conn.Endpoint
		buf []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		bufs := [][]byte{make([]byte, 1500)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, err := recvRelay(bufs, sizes, eps)
		if err != nil || n == 0 {
			done <- result{err: err}
			return
		}
		done <- result{ep: eps[0], buf: bufs[0][:sizes[0]]}
	}()

	// Retried: the relay session is up, but the far side's registration and
	// this send are not otherwise ordered.
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		if err := a.Send([][]byte{payload}, ep); err != nil {
			t.Fatalf("send over relay: %v", err)
		}
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatalf("receive: %v", r.err)
			}
			if !bytes.Equal(r.buf, payload) {
				t.Errorf("payload %q, want %q", r.buf, payload)
			}
			if r.ep != b.peerFor(aNode.Public()).ep {
				t.Error("the relayed packet was attributed to the wrong peer")
			}
			return
		case <-tick.C:
		case <-deadline:
			t.Fatal("the packet never arrived over the relay")
		}
	}
}

func waitRelay(t *testing.T, c *Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.RelayConnected() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the socket never connected to its relay")
}

// A self-observation inside the mesh range would tell peers to reach us
// through a tunnel to reach a tunnel.
func TestMeshAddressesAreNotAdvertised(t *testing.T) {
	c, _, _ := newConn(t)

	c.noteSelfObservation(netip.MustParseAddrPort("100.64.0.5:51820"))
	c.noteSelfObservation(netip.MustParseAddrPort("203.0.113.9:51820"))

	got := c.SelfEndpoints()
	if len(got) != 1 || got[0].Addr().String() != "203.0.113.9" {
		t.Errorf("advertised endpoints are %v, want just the public one", got)
	}
}

// The set is sorted so that an unchanged view does not look like a change to
// the control server and bump the netmap version on every poll.
func TestSelfEndpointsAreStable(t *testing.T) {
	c, _, _ := newConn(t)

	c.noteSelfObservation(netip.MustParseAddrPort("203.0.113.9:51820"))
	c.noteSelfObservation(netip.MustParseAddrPort("198.51.100.4:51820"))

	first := c.SelfEndpoints()
	for i := 0; i < 5; i++ {
		next := c.SelfEndpoints()
		if len(next) != len(first) {
			t.Fatalf("length changed between calls: %d then %d", len(first), len(next))
		}
		for j := range next {
			if next[j] != first[j] {
				t.Fatalf("order changed between calls: %v then %v", first, next)
			}
		}
	}
}

// An address several parties agree on is the one a peer should try first.
func TestConfirmedObservationsSortFirst(t *testing.T) {
	c, _, _ := newConn(t)

	lonely := netip.MustParseAddrPort("198.51.100.4:51820")
	agreed := netip.MustParseAddrPort("203.0.113.9:51820")

	c.noteSelfObservation(lonely)
	c.noteSelfObservation(agreed)
	c.noteSelfObservation(agreed)

	got := c.SelfEndpoints()
	if len(got) != 2 || got[0] != agreed {
		t.Errorf("endpoints are %v, want the twice-confirmed %s first", got, agreed)
	}
}

func TestLocalPortIsBoundBeforeWireGuardStarts(t *testing.T) {
	c, _, _ := newConn(t)
	if c.LocalPort() == 0 {
		t.Error("the socket has no port before Open; endpoint advertisement would have nothing to publish")
	}
}

// PeerStatus has to distinguish "this peer is unknown" from "this peer is
// known and has no path". A ping that confused the two would report a typo as
// a connectivity problem.
func TestPeerStatusReportsUnknownPeers(t *testing.T) {
	c, _, _ := newConn(t)

	stranger, _ := key.NewPrivate()
	if _, ok := c.PeerStatus(stranger.Public()); ok {
		t.Error("a peer the socket has never heard of reported a status")
	}

	peer, peerDisco := mustKeys(t)
	c.SetNetwork([]PeerConfig{{NodeKey: peer.Public(), DiscoKey: peerDisco.Public()}}, "", key.Public{})

	st, ok := c.PeerStatus(peer.Public())
	if !ok {
		t.Fatal("a configured peer has no status")
	}
	if st.DirectOK {
		t.Error("a peer that has never answered reports a direct path")
	}
}

// ProbeNow is what a person typing `makima ping` gets, and it has to be able
// to say when there was nothing to probe.
func TestProbeNowReportsUnknownPeers(t *testing.T) {
	c, _, _ := newConn(t)

	stranger, _ := key.NewPrivate()
	if c.ProbeNow(stranger.Public()) {
		t.Error("probing an unknown peer reported success")
	}

	peer, peerDisco := mustKeys(t)
	c.SetNetwork([]PeerConfig{{NodeKey: peer.Public(), DiscoKey: peerDisco.Public()}}, "", key.Public{})
	if !c.ProbeNow(peer.Public()) {
		t.Error("probing a known peer reported failure")
	}
}

// The relayed and direct timings are separate measurements, and the gap
// between them is the whole argument for hole punching. Folding one into the
// other would make a relay in another country indistinguishable from a direct
// path across the room.
func TestRelayLatencyIsKeptApartFromDirect(t *testing.T) {
	ps := newPeerState(key.Public{1})

	ps.mu.Lock()
	ps.relayLatency = 80 * time.Millisecond
	ps.mu.Unlock()
	ps.noteDirectRecv(netip.MustParseAddrPort("203.0.113.9:41641"))
	ps.mu.Lock()
	ps.latency = 9 * time.Millisecond
	ps.mu.Unlock()

	st := ps.status()
	if st.Latency != 9*time.Millisecond {
		t.Errorf("direct latency is %s", st.Latency)
	}
	if st.RelayLatency != 80*time.Millisecond {
		t.Errorf("relay latency is %s", st.RelayLatency)
	}
}

func mustKeys(t *testing.T) (node, disco key.Private) {
	t.Helper()
	var err error
	if node, err = key.NewPrivate(); err != nil {
		t.Fatal(err)
	}
	if disco, err = key.NewPrivate(); err != nil {
		t.Fatal(err)
	}
	return node, disco
}
