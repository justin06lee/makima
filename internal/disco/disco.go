// Package disco is the probe protocol that finds direct paths between peers.
//
// It exists because of a chicken-and-egg problem. Two nodes behind NAT can
// only discover a working path by sending each other packets and seeing what
// arrives — but until a path works, no WireGuard session exists, so there is
// no encrypted channel to negotiate over. Disco is that channel: a tiny,
// separately-keyed protocol that runs beside WireGuard on the same socket and
// answers exactly one question, "can you hear me at this address?"
//
// Its packets are sealed under the disco key rather than the node key, which
// is the reason for a third keypair. A probe is sprayed at unverified
// addresses, some of which belong to strangers; keying it separately means the
// worst an observer can do with a captured probe is learn that two disco keys
// are trying to meet. It cannot be replayed into the data path, and it proves
// nothing about the WireGuard key — which is what keeps the control plane's
// promise that only node-key signing can settle who is who.
//
// The wire format is fixed-size and unencrypted only in its header, so a
// receiver can tell a disco packet from a WireGuard packet before spending a
// decryption on it.
package disco

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/justin06lee/makima/internal/key"
)

// Magic prefixes every disco packet.
//
// It must not collide with WireGuard's framing, whose first byte is a message
// type of 1 through 4 followed by three zero bytes. A six-byte ASCII prefix
// starting with 'm' can never be mistaken for one in either direction.
var Magic = [6]byte{'m', 'a', 'k', 'd', 's', 'c'}

// headerLen is the plaintext prefix: magic, then the sender's disco key, then
// the nonce. All three must be readable before decryption is possible.
const headerLen = len(Magic) + key.Size + key.NonceSize

// MessageType distinguishes the two probe halves.
type MessageType byte

const (
	// TypePing asks "can you hear me at this address?"
	TypePing MessageType = 1

	// TypePong answers, echoing the transaction and reporting the address the
	// ping appeared to come from.
	TypePong MessageType = 2
)

// TxIDLen is the length of a probe's transaction ID.
//
// Twelve random bytes is enough that a pong can only match the ping it
// answers. That matching is what makes a pong meaningful: it proves the far
// end received *this* probe on *this* path, so the round-trip time and the
// address it validates are both trustworthy.
const TxIDLen = 12

// TxID identifies one probe.
type TxID [TxIDLen]byte

// Ping asks a peer to confirm a path.
//
// NodeKey travels inside the sealed payload so the receiver can bind a disco
// key to a WireGuard identity on first contact, without trusting anything
// unauthenticated on the outside of the packet.
type Ping struct {
	TxID    TxID
	NodeKey key.Public
}

// Pong confirms one.
//
// Src is where the ping appeared to come from, as seen by the responder. That
// single field is peer-to-peer STUN: a node behind NAT learns its own public
// address from any peer that answers, without a STUN server being involved at
// all.
type Pong struct {
	TxID TxID
	Src  netip.AddrPort
}

// ErrNotDisco reports a packet that is not disco at all.
var ErrNotDisco = errors.New("disco: not a disco packet")

// IsDiscoPacket reports whether b carries the disco magic.
//
// Cheap enough to run on every inbound datagram, which is the point: the
// receive path must classify before it can route, and a length check plus six
// bytes of comparison is as close to free as that gets.
func IsDiscoPacket(b []byte) bool {
	return len(b) >= headerLen && [6]byte(b[:6]) == Magic
}

// SenderKey extracts the claimed sender disco key from a packet's header.
//
// "Claimed" is exact: anyone can write any key here. It is only a hint telling
// the receiver which key to attempt decryption with, and the attempt is what
// establishes whether the claim was true.
func SenderKey(b []byte) (key.Public, error) {
	if !IsDiscoPacket(b) {
		return key.Public{}, ErrNotDisco
	}
	var k key.Public
	copy(k[:], b[len(Magic):len(Magic)+key.Size])
	return k, nil
}

// Seal encodes and encrypts a message to a peer's disco key.
func Seal(msg any, recipient key.Public, sender key.Private) ([]byte, error) {
	plain, err := encode(msg)
	if err != nil {
		return nil, err
	}

	nonce, sealed, err := key.Seal(plain, recipient, sender)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, headerLen+len(sealed))
	out = append(out, Magic[:]...)
	pub := sender.Public()
	out = append(out, pub[:]...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// Open decrypts a disco packet and decodes the message inside.
//
// Returns a *Ping or a *Pong. The sender's key is returned too, since it is
// only trustworthy after the payload has opened under it.
func Open(b []byte, recipient key.Private) (sender key.Public, msg any, err error) {
	if !IsDiscoPacket(b) {
		return key.Public{}, nil, ErrNotDisco
	}

	sender, err = SenderKey(b)
	if err != nil {
		return key.Public{}, nil, err
	}

	nonceStart := len(Magic) + key.Size
	nonce := b[nonceStart : nonceStart+key.NonceSize]
	sealed := b[headerLen:]

	plain, err := key.Open(sealed, nonce, sender, recipient)
	if err != nil {
		return key.Public{}, nil, err
	}

	msg, err = decode(plain)
	if err != nil {
		return key.Public{}, nil, err
	}
	return sender, msg, nil
}

func encode(msg any) ([]byte, error) {
	switch m := msg.(type) {
	case *Ping:
		b := make([]byte, 0, 1+TxIDLen+key.Size)
		b = append(b, byte(TypePing))
		b = append(b, m.TxID[:]...)
		b = append(b, m.NodeKey[:]...)
		return b, nil

	case *Pong:
		b := make([]byte, 0, 1+TxIDLen+19)
		b = append(b, byte(TypePong))
		b = append(b, m.TxID[:]...)
		b = appendAddrPort(b, m.Src)
		return b, nil

	default:
		return nil, fmt.Errorf("disco: cannot encode %T", msg)
	}
}

func decode(b []byte) (any, error) {
	if len(b) < 1+TxIDLen {
		return nil, errors.New("disco: message too short")
	}

	var tx TxID
	copy(tx[:], b[1:1+TxIDLen])
	rest := b[1+TxIDLen:]

	switch MessageType(b[0]) {
	case TypePing:
		if len(rest) < key.Size {
			return nil, errors.New("disco: ping is missing its node key")
		}
		p := &Ping{TxID: tx}
		copy(p.NodeKey[:], rest[:key.Size])
		return p, nil

	case TypePong:
		addr, err := parseAddrPort(rest)
		if err != nil {
			return nil, err
		}
		return &Pong{TxID: tx, Src: addr}, nil

	default:
		return nil, fmt.Errorf("disco: unknown message type %d", b[0])
	}
}

// appendAddrPort writes a length-tagged address so v4 and v6 share one format.
func appendAddrPort(b []byte, a netip.AddrPort) []byte {
	ip := a.Addr().Unmap()
	raw := ip.AsSlice()
	b = append(b, byte(len(raw)))
	b = append(b, raw...)
	return binary.BigEndian.AppendUint16(b, a.Port())
}

func parseAddrPort(b []byte) (netip.AddrPort, error) {
	if len(b) < 1 {
		return netip.AddrPort{}, errors.New("disco: truncated address")
	}
	n := int(b[0])
	if n != 4 && n != 16 {
		return netip.AddrPort{}, fmt.Errorf("disco: address length %d is neither v4 nor v6", n)
	}
	if len(b) < 1+n+2 {
		return netip.AddrPort{}, errors.New("disco: truncated address")
	}

	addr, ok := netip.AddrFromSlice(b[1 : 1+n])
	if !ok {
		return netip.AddrPort{}, errors.New("disco: malformed address")
	}
	port := binary.BigEndian.Uint16(b[1+n:])
	return netip.AddrPortFrom(addr, port), nil
}
