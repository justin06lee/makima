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

// MessageType distinguishes the messages that share the disco socket: the two
// probe halves, and the two halves of a serverless pairing.
type MessageType byte

const (
	// TypePing asks "can you hear me at this address?"
	TypePing MessageType = 1

	// TypePong answers, echoing the transaction and reporting the address the
	// ping appeared to come from.
	TypePong MessageType = 2

	// TypeKnock asks a machine that has published a pairing address to admit
	// the sender as a peer.
	TypeKnock MessageType = 3

	// TypeKnocked answers a knock, carrying whatever the knocker still needs
	// in order to configure the responder as a peer in return.
	TypeKnocked MessageType = 4
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

// Knock asks to be admitted to a serverless pairing.
//
// It travels on the same socket and under the same seal as a probe, which is
// what lets it arrive by whichever path exists — through the relay to a
// machine whose address nobody knows, or straight to a candidate endpoint on
// the same LAN. Pairing needs no transport of its own because path discovery
// already had to solve the harder version of the same problem.
//
// Every field is inside the sealed payload. Nothing about a knock is readable
// by the relay carrying it or by anyone watching the wire, including the fact
// that it is a knock rather than a probe.
type Knock struct {
	TxID TxID

	// NodeKey and Addr are what the responder needs to configure the knocker
	// as a WireGuard peer. Name is what it will be called.
	NodeKey key.Public
	Addr    netip.Addr
	Name    string

	// Token proves the knocker holds the pairing address it is knocking on,
	// binding any preshared key in that address to this exchange. Without it a
	// knock would rest entirely on the seal, which a leaked disco key would
	// defeat.
	Token []byte

	// Endpoints are where the knocker believes it can be reached, so the
	// responder can start probing immediately rather than waiting to be
	// probed. Hints, and treated as such.
	Endpoints []netip.AddrPort
}

// Knocked accepts a knock.
//
// It repeats what the pairing address already said. That is deliberate: an
// address may have been minted minutes or days ago, and a machine's endpoints
// change constantly. The acknowledgement is the first thing in the exchange
// that is current, so it is what the knocker actually configures from.
//
// A refused knock is answered with nothing at all. Saying "no" would confirm
// to anyone spraying knocks that this machine runs makima and is simply not
// listening right now, and there is no legitimate caller that benefits from
// knowing the difference between refused and absent.
type Knocked struct {
	TxID TxID

	NodeKey key.Public
	Addr    netip.Addr
	Name    string

	Endpoints []netip.AddrPort
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
// Returns a *Ping, *Pong, *Knock or *Knocked. The sender's key is returned
// too, since it is only trustworthy after the payload has opened under it.
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

	case *Knock:
		b := []byte{byte(TypeKnock)}
		b = append(b, m.TxID[:]...)
		b = append(b, m.NodeKey[:]...)
		b = appendAddr(b, m.Addr)
		b = appendBytes(b, []byte(m.Name))
		b = appendBytes(b, m.Token)
		return appendEndpoints(b, m.Endpoints), nil

	case *Knocked:
		b := []byte{byte(TypeKnocked)}
		b = append(b, m.TxID[:]...)
		b = append(b, m.NodeKey[:]...)
		b = appendAddr(b, m.Addr)
		b = appendBytes(b, []byte(m.Name))
		return appendEndpoints(b, m.Endpoints), nil

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

	case TypeKnock:
		k := &Knock{TxID: tx}
		var err error
		if rest, err = takeKey(rest, &k.NodeKey); err != nil {
			return nil, err
		}
		if rest, k.Addr, err = takeAddr(rest); err != nil {
			return nil, err
		}
		var name, token []byte
		if rest, name, err = takeBytes(rest); err != nil {
			return nil, err
		}
		if rest, token, err = takeBytes(rest); err != nil {
			return nil, err
		}
		k.Name, k.Token = string(name), token
		if k.Endpoints, err = takeEndpoints(rest); err != nil {
			return nil, err
		}
		return k, nil

	case TypeKnocked:
		k := &Knocked{TxID: tx}
		var err error
		if rest, err = takeKey(rest, &k.NodeKey); err != nil {
			return nil, err
		}
		if rest, k.Addr, err = takeAddr(rest); err != nil {
			return nil, err
		}
		var name []byte
		if rest, name, err = takeBytes(rest); err != nil {
			return nil, err
		}
		k.Name = string(name)
		if k.Endpoints, err = takeEndpoints(rest); err != nil {
			return nil, err
		}
		return k, nil

	default:
		return nil, fmt.Errorf("disco: unknown message type %d", b[0])
	}
}

// The knock messages are variable-length, which the fixed-shape probes are
// not, so they need a few primitives the probe codec never did. All of them
// are length-tagged and all of them refuse to read past the buffer: a knock
// arrives from someone who is not yet a peer, so its encoding is the one part
// of this package that parses genuinely untrusted input.

// appendBytes writes a length-prefixed byte string. Two bytes of length caps a
// field at 64KiB, which is far more than a hostname or a hash needs and far
// less than a datagram can carry.
func appendBytes(b, v []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

func takeBytes(b []byte) (rest, v []byte, err error) {
	if len(b) < 2 {
		return nil, nil, errors.New("disco: truncated length prefix")
	}
	n := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < n {
		return nil, nil, errors.New("disco: field claims more bytes than the packet holds")
	}
	return b[n:], b[:n], nil
}

func takeKey(b []byte, dst *key.Public) (rest []byte, err error) {
	if len(b) < key.Size {
		return nil, errors.New("disco: truncated key")
	}
	copy(dst[:], b[:key.Size])
	return b[key.Size:], nil
}

// appendAddr writes a bare IP with no port, length-tagged so v4 and v6 share
// one format. An invalid address encodes as zero bytes and decodes back to
// one, since a knock from a node that has no mesh address yet is legitimate.
func appendAddr(b []byte, a netip.Addr) []byte {
	if !a.IsValid() {
		return append(b, 0)
	}
	raw := a.Unmap().AsSlice()
	b = append(b, byte(len(raw)))
	return append(b, raw...)
}

func takeAddr(b []byte) (rest []byte, a netip.Addr, err error) {
	if len(b) < 1 {
		return nil, netip.Addr{}, errors.New("disco: truncated address")
	}
	n := int(b[0])
	b = b[1:]
	switch n {
	case 0:
		return b, netip.Addr{}, nil
	case 4, 16:
	default:
		return nil, netip.Addr{}, fmt.Errorf("disco: address length %d is neither v4 nor v6", n)
	}
	if len(b) < n {
		return nil, netip.Addr{}, errors.New("disco: truncated address")
	}
	addr, ok := netip.AddrFromSlice(b[:n])
	if !ok {
		return nil, netip.Addr{}, errors.New("disco: malformed address")
	}
	return b[n:], addr, nil
}

// maxEndpoints caps how many candidate paths one message may carry.
//
// A knock is parsed before its sender is anybody, so the count has to be
// bounded by the format rather than by trust. Sixteen is more interfaces than
// a machine plausibly has and still leaves the packet comfortably inside a
// datagram.
const maxEndpoints = 16

func appendEndpoints(b []byte, eps []netip.AddrPort) []byte {
	if len(eps) > maxEndpoints {
		eps = eps[:maxEndpoints]
	}
	b = append(b, byte(len(eps)))
	for _, e := range eps {
		b = appendAddrPort(b, e)
	}
	return b
}

func takeEndpoints(b []byte) ([]netip.AddrPort, error) {
	if len(b) < 1 {
		return nil, errors.New("disco: truncated endpoint list")
	}
	n := int(b[0])
	if n > maxEndpoints {
		return nil, fmt.Errorf("disco: %d endpoints exceeds the %d-endpoint limit", n, maxEndpoints)
	}
	b = b[1:]

	out := make([]netip.AddrPort, 0, n)
	for range n {
		// Every entry is a one-byte length, that many address bytes, and two
		// bytes of port. parseAddrPort validates the first two; the stride has
		// to be recomputed here because the entries are not fixed-width.
		if len(b) < 1 {
			return nil, errors.New("disco: truncated endpoint list")
		}
		size := 1 + int(b[0]) + 2
		if len(b) < size {
			return nil, errors.New("disco: truncated endpoint list")
		}
		ap, err := parseAddrPort(b[:size])
		if err != nil {
			return nil, err
		}
		out = append(out, ap)
		b = b[size:]
	}
	return out, nil
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
