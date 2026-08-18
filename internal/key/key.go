// Package key holds the Curve25519 keypairs makima nodes identify themselves
// with.
//
// A node carries three distinct keypairs, and keeping them separate is a
// deliberate security property rather than bookkeeping:
//
//	node     the WireGuard keypair. Encrypts actual traffic. Rotatable.
//	machine  identifies the device to the control server and encrypts the
//	         control channel. Never touches data traffic.
//	disco    signs and encrypts NAT-traversal probes, so path discovery can
//	         run before any WireGuard session exists and cannot be spoofed by
//	         an observer sitting on the wire.
//
// The control server only ever learns public halves. It therefore cannot
// decrypt traffic between nodes — the worst it can do is lie about who
// belongs to the network, which is the threat node-key signing addresses
// later on.
package key

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Size is the length of every key in this package, in bytes.
const Size = 32

// Private is the secret half of a Curve25519 keypair. It is always stored
// clamped, so Public is stable across calls.
type Private [Size]byte

// Public is the shareable half of a Curve25519 keypair.
type Public [Size]byte

// NewPrivate generates a clamped Curve25519 private key from the system CSPRNG.
func NewPrivate() (Private, error) {
	var p Private
	if _, err := rand.Read(p[:]); err != nil {
		return Private{}, fmt.Errorf("read entropy: %w", err)
	}
	p.clamp()
	return p, nil
}

// clamp applies the Curve25519 bit-fiddling WireGuard expects: clear the low
// three bits, clear the high bit, set the second-highest. Doing it at
// generation time means a key read back from disk needs no special handling.
func (p *Private) clamp() {
	p[0] &= 248
	p[31] &= 127
	p[31] |= 64
}

// Public derives the public half.
func (p Private) Public() Public {
	var pub Public
	// curve25519.ScalarBaseMult is deprecated in favour of X25519, but X25519
	// rejects low-order results; for a base-point multiply that can't happen,
	// and we want the infallible signature here.
	curve25519.ScalarBaseMult((*[Size]byte)(&pub), (*[Size]byte)(&p))
	return pub
}

// IsZero reports whether the key was never set.
func (p Private) IsZero() bool { return p == Private{} }

// IsZero reports whether the key was never set.
func (p Public) IsZero() bool { return p == Public{} }

// String renders the key base64-encoded, matching the wg(8) presentation
// format so keys can be pasted between makima and stock WireGuard tooling.
func (p Public) String() string { return base64.StdEncoding.EncodeToString(p[:]) }

// String deliberately redacts the secret. Use Base64 when you actually mean
// to serialise it, so leaking one to a log is never accidental.
func (p Private) String() string { return "privkey:[redacted]" }

// Base64 serialises the private key for storage on disk.
func (p Private) Base64() string { return base64.StdEncoding.EncodeToString(p[:]) }

// Hex renders the key for WireGuard's UAPI protocol, which speaks hex only.
func (p Private) Hex() string { return hex.EncodeToString(p[:]) }

// Hex renders the key for WireGuard's UAPI protocol, which speaks hex only.
func (p Public) Hex() string { return hex.EncodeToString(p[:]) }

// ErrBadKey reports a key that did not decode to the right length.
var ErrBadKey = errors.New("key: malformed or wrong length")

// ParsePrivate decodes a base64 private key and clamps it.
func ParsePrivate(s string) (Private, error) {
	b, err := decode(s)
	if err != nil {
		return Private{}, err
	}
	var p Private
	copy(p[:], b)
	p.clamp()
	return p, nil
}

// ParsePublic decodes a base64 public key.
func ParsePublic(s string) (Public, error) {
	b, err := decode(s)
	if err != nil {
		return Public{}, err
	}
	var p Public
	copy(p[:], b)
	return p, nil
}

func decode(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	if len(b) != Size {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrBadKey, len(b), Size)
	}
	return b, nil
}

// MarshalText lets public keys sit naturally in JSON config and wire messages.
func (p Public) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText parses the base64 form.
func (p *Public) UnmarshalText(b []byte) error {
	v, err := ParsePublic(string(b))
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// MarshalText serialises the secret. This is the one place a private key is
// allowed to become text, and it exists so a node can persist its own identity
// to disk — never so one can be sent anywhere.
func (p Private) MarshalText() ([]byte, error) { return []byte(p.Base64()), nil }

// UnmarshalText parses and clamps the base64 form.
func (p *Private) UnmarshalText(b []byte) error {
	v, err := ParsePrivate(string(b))
	if err != nil {
		return err
	}
	*p = v
	return nil
}
