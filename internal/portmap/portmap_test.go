package portmap

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestPCPRequestShape(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.50")
	req, nonce := pcpMapRequest(self, 51820, 7200)

	if len(req) != 60 {
		t.Fatalf("PCP MAP request is %d bytes, want 60", len(req))
	}
	if req[0] != 2 {
		t.Errorf("version %d, want 2", req[0])
	}
	if req[1] != 1 {
		t.Errorf("opcode %d, want 1 (MAP request)", req[1])
	}
	if got := binary.BigEndian.Uint32(req[4:8]); got != 7200 {
		t.Errorf("lifetime %d, want 7200", got)
	}
	if req[36] != 17 {
		t.Errorf("protocol %d, want 17 (UDP)", req[36])
	}
	if got := binary.BigEndian.Uint16(req[40:42]); got != 51820 {
		t.Errorf("internal port %d, want 51820", got)
	}
	if [12]byte(req[24:36]) != nonce {
		t.Error("the request does not carry the nonce it returned")
	}
}

// The nonce must be reproducible from the port alone, so a renewal after a
// restart still presents the one that created the mapping.
func TestPCPNonceIsDerivedFromThePort(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.50")

	_, a := pcpMapRequest(self, 51820, 7200)
	_, b := pcpMapRequest(self, 51820, 0)
	if a != b {
		t.Error("the same port produced two different nonces; a renewal would be rejected")
	}

	_, c := pcpMapRequest(self, 51821, 7200)
	if a == c {
		t.Error("two ports produced the same nonce")
	}
}

// buildPCPResponse assembles what a router would send back.
func buildPCPResponse(nonce [12]byte, result byte, externalPort uint16, external netip.Addr) []byte {
	b := make([]byte, 60)
	b[0] = 2
	b[1] = 0x81 // MAP, response bit
	b[3] = result
	copy(b[24:36], nonce[:])
	binary.BigEndian.PutUint16(b[42:44], externalPort)
	ext := external.As16()
	copy(b[44:60], ext[:])
	return b
}

func TestParsePCPSuccess(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.50")
	_, nonce := pcpMapRequest(self, 51820, 7200)

	external := netip.MustParseAddr("203.0.113.7")
	resp := buildPCPResponse(nonce, 0, 41641, external)

	got, err := parsePCPMapResponse(resp, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr() != external || got.Port() != 41641 {
		t.Errorf("mapped to %s, want %s:41641", got, external)
	}
}

// The nonce is what stops another host on the LAN from repointing a mapping it
// did not create, so a mismatch must be fatal.
func TestPCPNonceMismatchRejected(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.50")
	_, nonce := pcpMapRequest(self, 51820, 7200)

	var other [12]byte
	other[0] = 0xff

	resp := buildPCPResponse(other, 0, 41641, netip.MustParseAddr("203.0.113.7"))
	if _, err := parsePCPMapResponse(resp, nonce); err == nil {
		t.Error("a response carrying somebody else's nonce was accepted")
	}
}

func TestPCPErrorResultRejected(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.50")
	_, nonce := pcpMapRequest(self, 51820, 7200)

	// Result 2 is NOT_AUTHORIZED — the router refusing the mapping.
	resp := buildPCPResponse(nonce, 2, 41641, netip.MustParseAddr("203.0.113.7"))
	if _, err := parsePCPMapResponse(resp, nonce); err == nil {
		t.Error("a refused mapping was read as a success")
	}
}

// A router that reports no external address has not given us anything usable,
// and advertising 0.0.0.0 to peers would be worse than advertising nothing.
func TestPCPUnspecifiedExternalRejected(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.50")
	_, nonce := pcpMapRequest(self, 51820, 7200)

	resp := buildPCPResponse(nonce, 0, 41641, netip.MustParseAddr("0.0.0.0"))
	if _, err := parsePCPMapResponse(resp, nonce); err == nil {
		t.Error("a mapping with no external address was accepted")
	}
}

func TestPCPTruncatedResponseRejected(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.50")
	_, nonce := pcpMapRequest(self, 51820, 7200)

	if _, err := parsePCPMapResponse(make([]byte, 20), nonce); err == nil {
		t.Error("a truncated PCP response was parsed")
	}
}

// A response that is not a MAP reply must not be read as one.
func TestPCPWrongOpcodeRejected(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.50")
	_, nonce := pcpMapRequest(self, 51820, 7200)

	resp := buildPCPResponse(nonce, 0, 41641, netip.MustParseAddr("203.0.113.7"))
	resp[1] = 0x82 // PEER, not MAP

	if _, err := parsePCPMapResponse(resp, nonce); err == nil {
		t.Error("a non-MAP response was parsed as a mapping")
	}
}

// A client with no mapping must report none rather than a zero address that a
// caller might advertise.
func TestNoMappingReportsNothing(t *testing.T) {
	c := New(nil)
	if _, ok := c.External(); ok {
		t.Error("a fresh client claims to hold a mapping")
	}
}

func TestMapNeedsAPort(t *testing.T) {
	c := New(nil)
	if _, err := c.Map(nil, 0); err == nil {
		t.Error("mapping port zero was accepted")
	}
}
