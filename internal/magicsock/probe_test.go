package magicsock

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/disco"
	"github.com/justin06lee/makima/internal/key"
	"golang.zx2c4.com/wireguard/conn"
)

// drain runs a Conn's receive functions the way WireGuard would, so disco
// packets reaching it are handled. Stops when the test ends.
func drain(t *testing.T, c *Conn) {
	t.Helper()
	fns, _, err := c.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range fns {
		go func() {
			bufs := [][]byte{make([]byte, 2048)}
			sizes := make([]int, 1)
			eps := make([]conn.Endpoint, 1)
			for {
				if _, err := fn(bufs, sizes, eps); err != nil {
					return
				}
			}
		}()
	}
	t.Cleanup(func() { c.Close() })
}

func loopback(c *Conn) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), c.LocalPort())
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Two sockets that know each other's address find a direct path by probing,
// which is now the only way a path is found.
func TestProbingFindsADirectPath(t *testing.T) {
	a, aNode, aDisco := newConn(t)
	b, bNode, bDisco := newConn(t)
	drain(t, a)
	drain(t, b)

	a.SetNetwork([]PeerConfig{{NodeKey: bNode.Public(), DiscoKey: bDisco.Public(), Endpoints: []netip.AddrPort{loopback(b)}}}, "", key.Public{})
	b.SetNetwork([]PeerConfig{{NodeKey: aNode.Public(), DiscoKey: aDisco.Public(), Endpoints: []netip.AddrPort{loopback(a)}}}, "", key.Public{})

	a.probePeer(a.peerFor(bNode.Public()), true)
	waitFor(t, "a direct path from a to b", func() bool {
		addr, ok := a.peerFor(bNode.Public()).directPath()
		return ok && addr == loopback(b)
	})
}

// A ping somebody captured and sends again from their own address must not
// move the path there. It used to: a ping promoted the address it came from.
func TestReplayedPingDoesNotStealThePath(t *testing.T) {
	a, aNode, aDisco := newConn(t)
	b, bNode, bDisco := newConn(t)
	drain(t, b)

	b.SetNetwork([]PeerConfig{{NodeKey: aNode.Public(), DiscoKey: aDisco.Public(), Endpoints: []netip.AddrPort{loopback(a)}}}, "", key.Public{})

	// A ping from a to b, as anybody on the path would have seen it.
	ping, err := disco.Seal(&disco.Ping{TxID: disco.TxID{1}, NodeKey: aNode.Public()}, bDisco.Public(), aDisco)
	if err != nil {
		t.Fatal(err)
	}

	thief, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer thief.Close()
	if _, err := thief.WriteToUDPAddrPort(ping, loopback(b)); err != nil {
		t.Fatal(err)
	}

	// b answers the ping — and probes back — so wait for its pong to reach
	// the thief, which proves the ping was handled.
	thief.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	if _, _, err := thief.ReadFromUDPAddrPort(buf); err != nil {
		t.Fatalf("b never answered the replayed ping: %v", err)
	}
	if addr, ok := b.peerFor(aNode.Public()).directPath(); ok {
		t.Errorf("a replayed ping made %s the path to a", addr)
	}
	_ = bNode
}

// A pong has to come from the address its ping went to. A copy sent on from
// anywhere else is somebody on the path, and promoting its source would hand
// them the path.
func TestPongFromTheWrongAddressIsIgnored(t *testing.T) {
	a, _, aDisco := newConn(t)
	peerNode, peerDisco := mustKeys(t)
	a.SetNetwork([]PeerConfig{{NodeKey: peerNode.Public(), DiscoKey: peerDisco.Public()}}, "", key.Public{})
	ps := a.peerFor(peerNode.Public())

	pinged := netip.MustParseAddrPort("192.0.2.10:41641")
	tx := disco.TxID{7}
	ps.mu.Lock()
	ps.probes[tx] = &probe{addr: pinged, sent: time.Now()}
	ps.mu.Unlock()

	a.handlePong(ps, &disco.Pong{TxID: tx}, netip.MustParseAddrPort("203.0.113.66:9999"))
	if _, ok := ps.directPath(); ok {
		t.Fatal("a pong from an address nobody pinged promoted it")
	}

	a.handlePong(ps, &disco.Pong{TxID: tx}, pinged)
	if addr, ok := ps.directPath(); !ok || addr != pinged {
		t.Error("the real pong, from the pinged address, did not promote it")
	}
	_ = aDisco
}

// A WireGuard packet has not been authenticated when the socket sees it, so
// it can keep the path in use alive but never choose a new one.
func TestDataPacketDoesNotChooseThePath(t *testing.T) {
	ps := newPeerState(key.Public{1})
	stale := netip.MustParseAddrPort("192.168.1.5:41641")

	ps.noteDataRecv(stale)
	if _, ok := ps.directPath(); ok {
		t.Error("an unauthenticated packet chose the path")
	}

	best := netip.MustParseAddrPort("203.0.113.9:41641")
	ps.noteDirectRecv(best)
	ps.mu.Lock()
	ps.bestAt = time.Now().Add(-directTrust + time.Second)
	ps.mu.Unlock()
	ps.noteDataRecv(best)
	if addr, ok := ps.directPath(); !ok || addr != best {
		t.Error("traffic on the path in use did not keep it trusted")
	}
	ps.noteDataRecv(stale)
	if addr, _ := ps.directPath(); addr != best {
		t.Errorf("a packet from elsewhere moved the path to %s", addr)
	}
}

// Probing through the relay now comes back, and times the relayed path.
func TestRelayedProbeMeasuresTheRelay(t *testing.T) {
	relayAddr, relayKey := testRelay(t)
	a, aNode, aDisco := newConn(t)
	b, bNode, bDisco := newConn(t)
	drain(t, a)
	drain(t, b)

	a.SetNetwork([]PeerConfig{{NodeKey: bNode.Public(), DiscoKey: bDisco.Public(), RelayURL: relayAddr}}, relayAddr, relayKey)
	b.SetNetwork([]PeerConfig{{NodeKey: aNode.Public(), DiscoKey: aDisco.Public(), RelayURL: relayAddr}}, relayAddr, relayKey)
	waitRelay(t, a)
	waitRelay(t, b)

	ps := a.peerFor(bNode.Public())
	waitFor(t, "a relayed pong", func() bool {
		a.sendPingRelayed(ps, bDisco.Public())
		time.Sleep(50 * time.Millisecond)
		return a.peerFor(bNode.Public()).status().RelayLatency > 0
	})
}

// The control plane moving a relay to a new key at the same address — a
// relay reinstalled, its identity regenerated — has to be followed; the old
// connection pins the old key and can never register again.
func TestANewRelayKeyAtTheSameAddressIsFollowed(t *testing.T) {
	a, _, _ := newConn(t)
	k1, _ := key.NewPrivate()
	k2, _ := key.NewPrivate()

	a.SetNetwork(nil, "127.0.0.1:9", k1.Public())
	a.mu.RLock()
	first := a.relayClient
	a.mu.RUnlock()

	a.SetNetwork(nil, "127.0.0.1:9", k2.Public())
	a.mu.RLock()
	second, gotKey := a.relayClient, a.relayKey
	a.mu.RUnlock()

	if second == first || gotKey != k2.Public() {
		t.Error("a new relay key at the same address was ignored")
	}
}
