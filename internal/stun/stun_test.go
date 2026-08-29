package stun

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// buildResponse assembles a binding success response the way a server would.
func buildResponse(txID TxID, attrType uint16, val []byte) []byte {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], bindingSuccess)
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], txID[:])

	attr := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(attr[0:2], attrType)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(val)))
	copy(attr[4:], val)

	binary.BigEndian.PutUint16(b[2:4], uint16(len(attr)))
	return append(b, attr...)
}

// xorMappedV4 encodes an IPv4 address the way XOR-MAPPED-ADDRESS requires.
func xorMappedV4(addr netip.AddrPort) []byte {
	val := make([]byte, 8)
	val[1] = 0x01
	binary.BigEndian.PutUint16(val[2:4], addr.Port()^uint16(magicCookie>>16))

	ip := addr.Addr().As4()
	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], magicCookie)
	for i := range ip {
		val[4+i] = ip[i] ^ cookie[i]
	}
	return val
}

func TestRequestIsWellFormed(t *testing.T) {
	req, txID, err := Request()
	if err != nil {
		t.Fatal(err)
	}
	if len(req) != headerLen {
		t.Errorf("request is %d bytes, want %d", len(req), headerLen)
	}
	if binary.BigEndian.Uint16(req[0:2]) != bindingRequest {
		t.Error("not a binding request")
	}
	if binary.BigEndian.Uint32(req[4:8]) != magicCookie {
		t.Error("missing magic cookie")
	}
	if TxID(req[8:20]) != txID {
		t.Error("the returned transaction id is not the one in the packet")
	}
}

// Two requests must never share a transaction id, or a forged response for one
// would be accepted as the answer to the other.
func TestTransactionIDsAreDistinct(t *testing.T) {
	seen := make(map[TxID]bool)
	for i := 0; i < 64; i++ {
		_, tx, err := Request()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tx] {
			t.Fatal("a transaction id repeated")
		}
		seen[tx] = true
	}
}

func TestParseXorMappedAddress(t *testing.T) {
	want := netip.MustParseAddrPort("203.0.113.7:41641")
	_, txID, _ := Request()

	resp := buildResponse(txID, attrXorMappedAd, xorMappedV4(want))

	got, ok := ParseResponse(resp)
	if !ok {
		t.Fatal("a well-formed response did not parse")
	}
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// The pre-RFC-5389 plain form is still emitted by some servers.
func TestParseMappedAddress(t *testing.T) {
	want := netip.MustParseAddrPort("198.51.100.9:3478")
	_, txID, _ := Request()

	val := make([]byte, 8)
	val[1] = 0x01
	binary.BigEndian.PutUint16(val[2:4], want.Port())
	ip := want.Addr().As4()
	copy(val[4:], ip[:])

	got, ok := ParseResponse(buildResponse(txID, attrMappedAddr, val))
	if !ok {
		t.Fatal("a MAPPED-ADDRESS response did not parse")
	}
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// Attributes are padded to a four-byte boundary. Walking without accounting
// for the padding lands in the middle of the next attribute and produces
// garbage rather than an error, which is the worst possible outcome.
func TestSkipsPaddedAttributes(t *testing.T) {
	want := netip.MustParseAddrPort("192.0.2.55:1234")
	_, txID, _ := Request()

	// A SOFTWARE attribute of 5 bytes, which needs 3 bytes of padding, ahead
	// of the one we actually want.
	software := []byte("mak\x00\x00")
	softAttr := make([]byte, 4+len(software)+3)
	binary.BigEndian.PutUint16(softAttr[0:2], 0x8022)
	binary.BigEndian.PutUint16(softAttr[2:4], uint16(len(software)))
	copy(softAttr[4:], software)

	xor := xorMappedV4(want)
	xorAttr := make([]byte, 4+len(xor))
	binary.BigEndian.PutUint16(xorAttr[0:2], attrXorMappedAd)
	binary.BigEndian.PutUint16(xorAttr[2:4], uint16(len(xor)))
	copy(xorAttr[4:], xor)

	body := append(softAttr, xorAttr...)

	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], bindingSuccess)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(body)))
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], txID[:])
	b = append(b, body...)

	got, ok := ParseResponse(b)
	if !ok {
		t.Fatal("a response with a padded leading attribute did not parse")
	}
	if got != want {
		t.Errorf("got %s, want %s — padding was probably mishandled", got, want)
	}
}

// The classifier shares a socket with WireGuard and disco, so it must not
// claim their packets.
func TestIsRejectsOtherProtocols(t *testing.T) {
	for _, typ := range []byte{1, 2, 3, 4} {
		wg := make([]byte, 148)
		wg[0] = typ
		if Is(wg) {
			t.Errorf("a WireGuard type-%d message was mistaken for STUN", typ)
		}
	}

	disco := make([]byte, 100)
	copy(disco, "makdsc")
	if Is(disco) {
		t.Error("a disco packet was mistaken for STUN")
	}

	if Is(nil) || Is(make([]byte, 8)) {
		t.Error("a short buffer was mistaken for STUN")
	}
}

func TestResponseTxIDMatching(t *testing.T) {
	_, txID, _ := Request()
	resp := buildResponse(txID, attrXorMappedAd, xorMappedV4(netip.MustParseAddrPort("192.0.2.1:1")))

	got, ok := ResponseTxID(resp)
	if !ok {
		t.Fatal("a success response had no readable transaction id")
	}
	if got != txID {
		t.Error("the transaction id did not match the request")
	}

	// A binding *request* is not a response and must not match.
	req, _, _ := Request()
	if _, ok := ResponseTxID(req); ok {
		t.Error("a request was read as a response")
	}
}

func TestTruncatedResponsesRejected(t *testing.T) {
	_, txID, _ := Request()
	resp := buildResponse(txID, attrXorMappedAd, xorMappedV4(netip.MustParseAddrPort("192.0.2.1:1")))

	// An attribute length that runs past the end of the message.
	bad := append([]byte(nil), resp...)
	binary.BigEndian.PutUint16(bad[2:4], 0xffff)
	if _, ok := ParseResponse(bad); ok {
		t.Error("a response claiming more attributes than it carries was parsed")
	}

	if _, ok := ParseResponse(resp[:headerLen+4]); ok {
		t.Error("a truncated attribute was parsed")
	}
}
