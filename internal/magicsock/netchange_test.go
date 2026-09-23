package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// A laptop that leaves the house must stop trusting the LAN path it had to
// the desktop, or it sends everything down a dead path — and nothing over the
// relay — for most of a minute.
func TestNetworkChangeForgetsConfirmedPaths(t *testing.T) {
	c, _, _ := newConn(t)
	peer, _ := key.NewPrivate()
	lan := netip.MustParseAddrPort("192.168.1.253:51820")

	c.SetNetwork([]PeerConfig{{NodeKey: peer.Public(), Endpoints: []netip.AddrPort{lan}}}, "", key.Public{})
	ps := c.peerFor(peer.Public())
	ps.noteDirectRecv(lan)
	if _, ok := ps.directPath(); !ok {
		t.Fatal("setup: no direct path")
	}
	c.noteSelfObservation(netip.MustParseAddrPort("203.0.113.7:51820"))

	c.NetworkChanged()

	if addr, ok := ps.directPath(); ok {
		t.Errorf("still trusting %s after the network changed", addr)
	}
	if got := c.SelfEndpoints(); len(got) != 0 {
		t.Errorf("still advertising the old network's public address: %v", got)
	}
	// The candidates survive: the peer may well still be at one of them, and
	// they are what the first packets after the move are sent to.
	if st := ps.status(); len(st.Candidates) != 1 {
		t.Errorf("candidates = %v", st.Candidates)
	}
}

// The relay connection was made from an address the machine no longer has.
// It has to be dialled again, not left for TCP to give up on.
func TestNetworkChangeRedialsTheRelay(t *testing.T) {
	addr, relayKey := testRelay(t)
	c, _, _ := newConn(t)
	c.SetNetwork(nil, addr, relayKey)

	deadline := time.Now().Add(5 * time.Second)
	for !c.RelayConnected() {
		if time.Now().After(deadline) {
			t.Fatal("relay never connected")
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.mu.RLock()
	before := c.relayClient
	c.mu.RUnlock()

	c.NetworkChanged()

	c.mu.RLock()
	after, url := c.relayClient, c.relayURL
	c.mu.RUnlock()
	if after == before {
		t.Fatal("the old relay connection was kept")
	}
	if url != addr {
		t.Fatalf("relay URL = %q, want %q", url, addr)
	}
	for !c.RelayConnected() {
		if time.Now().After(deadline) {
			t.Fatal("relay never reconnected")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
