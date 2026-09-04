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
//
// Alongside the three keypairs there is one symmetric secret, Shared: an
// optional WireGuard preshared key. It authenticates nobody and belongs to a
// pair of nodes rather than to either of them, which is why it is a separate
// type that can never be mistaken for an identity.
package key

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Size is the length of every key in this package, in bytes.
const Size = 32

// NonceSize is the length of a NaCl box nonce.
const NonceSize = 24

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

// Seal encrypts plain to recipient, authenticated as sender, and returns the
// fresh nonce alongside the ciphertext.
//
// Every protocol in makima that needs a confidential, authenticated message
// between two keyholders routes through here — the control channel, the relay
// handshake, and disco probes alike. There is no separate signature step
// anywhere: only the holder of the matching private key can produce something
// that opens, so a successful decryption *is* the proof of identity. Keeping
// that one primitive in one place is what makes that claim checkable.
func Seal(plain []byte, recipient Public, sender Private) (nonce, sealed []byte, err error) {
	var n [NonceSize]byte
	if _, err := rand.Read(n[:]); err != nil {
		return nil, nil, fmt.Errorf("read nonce entropy: %w", err)
	}
	sealed = box.Seal(nil, plain, &n, (*[Size]byte)(&recipient), (*[Size]byte)(&sender))
	return n[:], sealed, nil
}

// ErrNotAuthenticated reports a payload that did not open.
//
// Deliberately one error for every failure mode: a caller cannot distinguish
// "wrong key" from "tampered ciphertext", so a prober learns nothing about
// which keys we hold by watching how we fail.
var ErrNotAuthenticated = errors.New("key: payload failed to authenticate")

// Open decrypts a payload from sender.
func Open(sealed, nonce []byte, sender Public, recipient Private) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("%w: nonce is %d bytes, want %d", ErrNotAuthenticated, len(nonce), NonceSize)
	}
	var n [NonceSize]byte
	copy(n[:], nonce)

	plain, ok := box.Open(nil, sealed, &n, (*[Size]byte)(&sender), (*[Size]byte)(&recipient))
	if !ok {
		return nil, ErrNotAuthenticated
	}
	return plain, nil
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

// Shared is a WireGuard preshared key: 32 bytes of symmetric secret mixed into
// the handshake alongside the Curve25519 exchange.
//
// It is not a replacement for the keypairs and does not authenticate anyone —
// two peers with the same Shared and no matching node keys still cannot talk.
// What it buys is a hedge against Curve25519 itself: an adversary recording
// traffic today and breaking X25519 later — with a quantum computer or
// otherwise — still faces a symmetric secret they never saw on the wire.
// WireGuard's own protocol note calls this the post-quantum escape hatch, and
// it costs one extra field.
//
// Distinct from Private because the two are never interchangeable: a Shared
// has no public half, is symmetric, and must reach the far end by some channel
// that already exists. In makima it travels inside a pairing address, which is
// handed over out of band precisely so this is possible.
type Shared [Size]byte

// NewShared generates a preshared key from the system CSPRNG.
func NewShared() (Shared, error) {
	var s Shared
	if _, err := rand.Read(s[:]); err != nil {
		return Shared{}, fmt.Errorf("read entropy: %w", err)
	}
	return s, nil
}

// IsZero reports whether no preshared key was set.
//
// The zero value is meaningful: WireGuard treats an all-zero preshared key as
// "none", so a peer without one needs no special case anywhere.
func (s Shared) IsZero() bool { return s == Shared{} }

// String redacts the secret, matching Private. A preshared key leaked to a log
// is as bad as a private one, and the only way to be sure that never happens
// by accident is for the default rendering to refuse.
func (s Shared) String() string { return "psk:[redacted]" }

// Base64 serialises the preshared key, for storage and for a pairing address.
func (s Shared) Base64() string { return base64.StdEncoding.EncodeToString(s[:]) }

// Hex renders it for WireGuard's UAPI protocol, which speaks hex only.
func (s Shared) Hex() string { return hex.EncodeToString(s[:]) }

// ParseShared decodes a base64 preshared key.
func ParseShared(str string) (Shared, error) {
	b, err := decode(str)
	if err != nil {
		return Shared{}, err
	}
	var s Shared
	copy(s[:], b)
	return s, nil
}

// MarshalText serialises the secret so it can sit in a config file or a
// pairing address. As with Private, this is the one sanctioned way for it to
// become text.
func (s Shared) MarshalText() ([]byte, error) { return []byte(s.Base64()), nil }

// UnmarshalText parses the base64 form.
func (s *Shared) UnmarshalText(b []byte) error {
	v, err := ParseShared(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}
