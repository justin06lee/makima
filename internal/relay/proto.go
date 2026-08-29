// Package relay is the fallback path: a forwarder that carries WireGuard
// packets between two nodes that cannot reach each other directly.
//
// It is deliberately dumb. A relay learns which node key sits on which
// connection and copies frames between them, and that is the entire service.
// It never holds a WireGuard key, never decrypts a payload, and cannot tell
// one node's traffic from another's beyond the routing header. Running one
// therefore costs nothing in confidentiality — which is what makes it
// reasonable to hand a relay address to a stranger's node, and why the mesh
// can treat "start relayed, upgrade to direct" as the normal case rather than
// a degraded one.
//
// The transport is TCP. UDP would avoid head-of-line blocking, but a relay
// exists precisely for nodes whose UDP is being interfered with, and a plain
// TCP connection to a well-known port is the thing that survives the widest
// range of hostile middleboxes. A relayed path is slow by definition; the
// point is that it works everywhere, and M3's job is to leave it as soon as
// possible.
package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/justin06lee/makima/internal/key"
)

// ProtocolVersion guards against a node and relay disagreeing about framing.
const ProtocolVersion = 1

// magic prefixes the server's first bytes. A client that connects to the wrong
// port should fail immediately with a clear error rather than block forever
// waiting for a handshake that is never coming.
var magic = [8]byte{'m', 'a', 'k', 'i', 'r', 'l', 'y', ProtocolVersion}

// DefaultPort is where a relay listens. 3478 is the STUN port, chosen for the
// same reason Tailscale reuses well-known ports: traffic to it is unremarkable
// and rarely filtered outright.
const DefaultPort = 3478

// frameType identifies a frame's payload.
type frameType byte

const (
	// frameServerHello is the relay introducing itself and issuing a
	// challenge. Server to client, always first.
	frameServerHello frameType = 1

	// frameClientHello answers the challenge, proving the client holds the
	// private half of the node key it is claiming.
	frameClientHello frameType = 2

	// frameSendPacket asks the relay to forward to another node.
	// Payload: [32]byte destination node key, then the WireGuard packet.
	frameSendPacket frameType = 3

	// frameRecvPacket delivers a forwarded packet.
	// Payload: [32]byte source node key, then the WireGuard packet.
	frameRecvPacket frameType = 4

	// framePing and framePong measure liveness and round-trip time. Payload is
	// eight opaque bytes echoed back unchanged.
	framePing frameType = 5
	framePong frameType = 6
)

// maxFrameSize bounds a single frame. A WireGuard packet at the default MTU is
// well under 1500 bytes; the headroom is for the routing header and for a
// future jumbo path, and the cap exists so a hostile peer cannot make the
// relay allocate without limit.
const maxFrameSize = 64 << 10

// keySize is the length of the routing header on a packet frame.
const keySize = key.Size

// ErrFrameTooLarge reports a frame that exceeded maxFrameSize.
var ErrFrameTooLarge = errors.New("relay: frame exceeds maximum size")

// writeFrame emits one length-prefixed frame.
//
// The header is fixed at five bytes — one type, four length — so a reader
// never has to guess how much to buffer before it knows the rest.
func writeFrame(w io.Writer, t frameType, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}

	var hdr [5]byte
	hdr[0] = byte(t)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))

	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one frame into buf, which must be at least maxFrameSize.
//
// Returning a subslice of the caller's buffer rather than a fresh allocation
// is what keeps a busy relay from generating garbage per packet: the read loop
// owns one buffer for the life of the connection.
func readFrame(r io.Reader, buf []byte) (frameType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}

	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxFrameSize {
		// Do not attempt to resynchronise. A length this large means the
		// stream is not what we think it is, and reading past it would only
		// produce more garbage.
		return 0, nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	if int(n) > len(buf) {
		return 0, nil, fmt.Errorf("relay: frame of %d bytes exceeds the %d-byte read buffer", n, len(buf))
	}
	if n == 0 {
		return frameType(hdr[0]), nil, nil
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, nil, err
	}
	return frameType(hdr[0]), buf[:n], nil
}

// serverHello is the relay's opening frame.
//
// The challenge is what makes the handshake a proof rather than a claim: the
// client must seal it under the node key it is asserting, so a connection
// cannot register a key it does not hold. Without that, anyone could claim a
// victim's node key and quietly become a black hole for their relayed traffic.
type serverHello struct {
	Version   int        `json:"version"`
	RelayKey  key.Public `json:"relay_key"`
	Challenge []byte     `json:"challenge"`
}

// clientHello answers it.
//
// Nonce and Sealed are a NaCl box of the challenge, addressed to the relay's
// key and signed by the node key. Opening it is the entire authentication
// step, matching how the control channel treats a successful decryption as
// proof of identity.
type clientHello struct {
	Version int        `json:"version"`
	NodeKey key.Public `json:"node_key"`
	Nonce   []byte     `json:"nonce"`
	Sealed  []byte     `json:"sealed"`
}

// challengeSize is the length of the random challenge. 32 bytes is far past
// any collision concern and costs one read from the CSPRNG per connection.
const challengeSize = 32
