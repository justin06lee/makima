package magicsock

import (
	"net/netip"
	"testing"
	"time"
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
