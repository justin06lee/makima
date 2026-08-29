// Package stun asks a public server what address this node's packets appear to
// come from.
//
// A machine behind NAT cannot see its own public address. Its interfaces know
// only the private one, and the mapping the router creates exists nowhere the
// machine can read. STUN is the minimal trick that recovers it: send a packet
// to a server that will tell you what source address it saw, and the answer is
// the outside of your own NAT.
//
// This package is only the codec — build a request, recognise a response, read
// the address out of it. It deliberately owns no socket, because the answer is
// only meaningful if the request left the *same* socket WireGuard uses: a NAT
// gives each socket its own mapping, so a STUN query from a socket of its own
// would report an address that nothing can actually be reached at. That result
// looks entirely plausible and is completely useless, which makes it the worst
// possible kind of bug. Keeping the socket out of this package means the
// mistake cannot be made here.
//
// Only the binding request from RFC 5389 is implemented — no authentication,
// no TURN, no ICE. Everything makima needs is one question with one answer;
// the rest of the specification exists for negotiations that disco does
// itself.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// DefaultServers are public STUN servers.
//
// Several, from different operators, because any one of them can be down or
// blocked on a given network, and a node that cannot learn its own address
// falls back to being relay-only.
var DefaultServers = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun1.l.google.com:19302",
}

const (
	bindingRequest  = 0x0001
	bindingSuccess  = 0x0101
	magicCookie     = 0x2112A442
	attrXorMappedAd = 0x0020
	attrMappedAddr  = 0x0001
	headerLen       = 20
)

// TxID identifies one binding transaction.
type TxID [12]byte

// Request builds a binding request and the transaction ID that identifies its
// answer.
func Request() ([]byte, TxID, error) {
	var txID TxID
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, txID, fmt.Errorf("stun: read entropy: %w", err)
	}

	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], bindingRequest)
	binary.BigEndian.PutUint16(b[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], txID[:])
	return b, txID, nil
}

// Is reports whether a packet looks like STUN.
//
// Used to classify traffic on a socket shared with WireGuard and disco. The
// magic cookie is what makes this reliable rather than a guess: it is a fixed
// 32-bit value at a fixed offset that no WireGuard message type can produce.
func Is(b []byte) bool {
	if len(b) < headerLen {
		return false
	}
	// The two most significant bits of a STUN message type are always zero,
	// which is the other half of the disambiguation RFC 5389 designed in.
	if b[0]&0xc0 != 0 {
		return false
	}
	return binary.BigEndian.Uint32(b[4:8]) == magicCookie
}

// ResponseTxID reports which transaction a packet answers.
func ResponseTxID(b []byte) (TxID, bool) {
	if !Is(b) {
		return TxID{}, false
	}
	if binary.BigEndian.Uint16(b[0:2]) != bindingSuccess {
		return TxID{}, false
	}
	return TxID(b[8:20]), true
}

// ParseResponse extracts the mapped address from a success response.
//
// The caller is expected to have matched the transaction ID first; on a socket
// that also carries WireGuard and disco traffic, that check is what separates
// an answer to our question from a packet that merely happens to be here.
func ParseResponse(b []byte) (netip.AddrPort, bool) {
	if !Is(b) {
		return netip.AddrPort{}, false
	}
	if binary.BigEndian.Uint16(b[0:2]) != bindingSuccess {
		return netip.AddrPort{}, false
	}

	length := int(binary.BigEndian.Uint16(b[2:4]))
	if headerLen+length > len(b) {
		return netip.AddrPort{}, false
	}
	attrs := b[headerLen : headerLen+length]

	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		alen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+alen > len(attrs) {
			return netip.AddrPort{}, false
		}
		val := attrs[4 : 4+alen]

		switch typ {
		case attrXorMappedAd:
			if addr, ok := parseXorMapped(val, b[4:20]); ok {
				return addr, true
			}
		case attrMappedAddr:
			// The pre-RFC-5389 form. Still emitted by some servers, and
			// accepted because a plain address is no harder to read than an
			// obfuscated one.
			if addr, ok := parseMapped(val); ok {
				return addr, true
			}
		}

		// Attributes are padded to a four-byte boundary; skipping without the
		// padding walks straight into the middle of the next one.
		advance := 4 + alen
		if pad := alen % 4; pad != 0 {
			advance += 4 - pad
		}
		if advance > len(attrs) {
			break
		}
		attrs = attrs[advance:]
	}
	return netip.AddrPort{}, false
}

// parseXorMapped decodes XOR-MAPPED-ADDRESS.
//
// The XOR exists so that a NAT rewriting addresses inside packet payloads —
// which some genuinely do — cannot silently corrupt the answer, since the
// obfuscated bytes do not look like the address it is scanning for.
func parseXorMapped(val, cookieAndTx []byte) (netip.AddrPort, bool) {
	if len(val) < 4 {
		return netip.AddrPort{}, false
	}

	port := binary.BigEndian.Uint16(val[2:4]) ^ uint16(magicCookie>>16)

	switch val[1] {
	case 0x01: // IPv4
		if len(val) < 8 {
			return netip.AddrPort{}, false
		}
		var ip [4]byte
		for i := range ip {
			ip[i] = val[4+i] ^ cookieAndTx[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom4(ip), port), true

	case 0x02: // IPv6
		if len(val) < 20 {
			return netip.AddrPort{}, false
		}
		var ip [16]byte
		for i := range ip {
			ip[i] = val[4+i] ^ cookieAndTx[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom16(ip), port), true
	}
	return netip.AddrPort{}, false
}

func parseMapped(val []byte) (netip.AddrPort, bool) {
	if len(val) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(val[2:4])

	switch val[1] {
	case 0x01:
		if len(val) < 8 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(val[4:8])), port), true
	case 0x02:
		if len(val) < 20 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(val[4:20])), port), true
	}
	return netip.AddrPort{}, false
}
