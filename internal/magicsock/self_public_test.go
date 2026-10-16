package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/disco"
	"github.com/justin06lee/makima/internal/key"
)

// Only an address the internet could send to counts as a peer telling us our
// public address. A peer on the same LAN reporting 192.168.1.20 has answered
// a different question, and skipping STUN on the strength of it would leave a
// node with no public address to advertise at all.
func TestIsPublic(t *testing.T) {
	public := []string{"107.214.144.123", "2600:1702:891b:aa00::28", "::ffff:107.214.144.123"}
	private := []string{"192.168.1.20", "10.0.0.5", "172.16.3.4", "127.0.0.1", "fe80::1", "10.77.0.2", "100.64.0.9", "fd00::1"}

	for _, s := range public {
		if !isPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should count as public", s)
		}
	}
	for _, s := range private {
		if isPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should not count as public", s)
		}
	}
}

// A peer's report stands in for STUN only while it is fresh: a laptop that
// has moved since has a different public address, and needs asking again.
func TestAPeerReportExpires(t *testing.T) {
	var c Conn
	if c.PeerSawUsPublicly() {
		t.Error("reported seen with no report at all")
	}

	c.peerSawPublic = time.Now()
	if !c.PeerSawUsPublicly() {
		t.Error("a fresh report was not counted")
	}

	c.peerSawPublic = time.Now().Add(-observationTTL - time.Second)
	if c.PeerSawUsPublicly() {
		t.Error("a stale report still counted")
	}
}

// A peer that sees this machine at its IPv6 address has said nothing about
// the IPv4 NAT in front of it, which is what STUN is asked about. Counting
// it would stop the STUN queries that keep the public IPv4 address — the
// one most peers reach — advertised.
func TestAPeerSeeingUsOverIPv6DoesNotStandInForSTUN(t *testing.T) {
	c, _, _ := newConn(t)
	peer, _ := key.NewPrivate()
	ps := c.peerFor(peer.Public())

	pong := func(path, seen string) {
		tx, _ := newTxID()
		src := netip.MustParseAddrPort(path)
		ps.mu.Lock()
		ps.probes[tx] = &probe{addr: src, sent: time.Now()}
		ps.mu.Unlock()
		c.handlePong(ps, &disco.Pong{TxID: tx, Src: netip.MustParseAddrPort(seen)}, src)
	}

	pong("[2600:1010:b228:a823::5]:51820", "[2600:1702:891b:aa00:7ad3:ffe1:1b5b:ee6f]:51820")
	if c.PeerSawUsPublicly() {
		t.Error("an IPv6 sighting stood in for STUN")
	}
	pong("174.239.164.183:2504", "107.214.144.123:6505")
	if !c.PeerSawUsPublicly() {
		t.Error("an IPv4 sighting did not")
	}
}
