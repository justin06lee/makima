// Package pair is the serverless half of makima: two machines meeting with no
// control plane between them.
//
// The rest of makima is built around a control server that knows the mesh —
// who is in it, what addresses they hold, which relay each one uses. That is
// the right shape for a network you keep. It is the wrong shape for two
// machines that want to talk once, or for someone evaluating makima who does
// not yet want to run a server to find out whether it works.
//
// A pairing address is the whole alternative. It is one pasteable string
// carrying everything the far end needs to reach a machine and nothing else:
// its two public keys, the mesh address it answers on, optionally a preshared
// key, optionally a relay to meet at, and whatever endpoints it currently
// believes it can be reached at. There is no membership, no policy, and
// nothing to run. Two nodes meet at the relay keyed by public key — or
// directly, if either can be reached — and then punch a direct path exactly as
// a managed mesh does.
//
// The relay, when there is one, is the only fixed point. It is also the one
// component that was already untrusted: it forwards frames it cannot decrypt
// between node keys it cannot impersonate, which is what makes it reasonable
// to meet at one you do not own.
//
// An address is a bearer credential, like an invite. Whoever holds it can ask
// to pair. Unlike an invite it is not enough on its own: the far end has to be
// listening for a knock at the time, which is what `makima pair` opens and
// what closes again when its window expires. The encoding is opaque only so
// the string survives a chat window intact and fails loudly when truncated.
package pair

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// DefaultWindow is how long a machine listens for a knock by default.
//
// Long enough to walk to another machine and paste something, short enough
// that forgetting about it is not a standing invitation. A window that never
// closed would be a listening service somebody stopped thinking about, which
// is the thing pairing is specifically trying not to be.
const DefaultWindow = 10 * time.Minute

// Prefix marks a string as a pairing address.
//
// Distinct from the invite prefix so that pasting one where the other belongs
// says which is which, rather than failing somewhere inside a base64 decoder.
const Prefix = "mkp1_"

// Address is everything needed to reach one machine without a control plane.
type Address struct {
	// NodeKey is the WireGuard identity. The relay routes by it, and it is
	// what the far end configures as a peer.
	NodeKey key.Public `json:"n"`

	// DiscoKey authenticates path probes, and is what a knock is sealed to.
	//
	// It doubles as the pairing secret in the no-preshared-key case: a disco
	// key appears nowhere except in an address, so being able to seal to it is
	// itself evidence of holding one.
	DiscoKey key.Public `json:"d"`

	// Addr is the mesh address this machine answers on. Derived from NodeKey
	// by MeshAddr, but carried explicitly so an address minted today still
	// works if that derivation is ever changed.
	Addr netip.Addr `json:"a"`

	// Name is what the far end will call this machine. Cosmetic.
	Name string `json:"m,omitempty"`

	// PSK is an optional preshared key for the tunnel this address sets up.
	//
	// Carrying it here is what makes it usable at all: a symmetric secret has
	// to arrive out of band, and the address is already the out-of-band
	// channel. It also binds the pairing itself — see Token.
	PSK key.Shared `json:"p,omitzero"`

	// Relay is where this machine can be met when no direct path exists, and
	// RelayKey is the identity it will present. Empty means no relay, which
	// is a working configuration whenever one side is directly reachable —
	// the same LAN, a public address, a forwarded port.
	Relay    string     `json:"r,omitempty"`
	RelayKey key.Public `json:"rk,omitzero"`

	// Endpoints are addresses this machine believes it can be reached at.
	// Hints, and possibly stale: they are tried, not trusted.
	Endpoints []netip.AddrPort `json:"e,omitempty"`
}

// Encode renders an address as the single string a person pastes.
func Encode(a Address) (string, error) {
	if a.NodeKey.IsZero() {
		return "", errors.New("pair: no node key")
	}
	if a.DiscoKey.IsZero() {
		return "", errors.New("pair: no disco key")
	}
	if !a.Addr.IsValid() {
		return "", errors.New("pair: no mesh address")
	}
	if a.Relay == "" && len(a.Endpoints) == 0 {
		return "", errors.New("pair: no relay and no endpoints — nothing to meet at")
	}

	payload, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("pair: encode: %w", err)
	}
	// Unpadded URL-safe base64, matching invites: no "=" for a chat client to
	// swallow, no "/" for a URL to reinterpret, and it double-clicks as one
	// word.
	return Prefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

// Decode parses a pasted address.
//
// Tolerant of what a string picks up on its way through a human: surrounding
// whitespace, a shell's quotes, a prefix typed in the wrong case.
func Decode(s string) (Address, error) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	s = strings.TrimSpace(s)

	if s == "" {
		return Address{}, errors.New("pair: empty")
	}
	if len(s) <= len(Prefix) || !strings.EqualFold(s[:len(Prefix)], Prefix) {
		if strings.HasPrefix(s, "mk1_") {
			return Address{}, errors.New("pair: that is an invite, not a pairing address — use 'makima join' with it")
		}
		return Address{}, fmt.Errorf("pair: %q is not a pairing address (they start with %s)", elide(s), Prefix)
	}

	raw, err := base64.RawURLEncoding.DecodeString(s[len(Prefix):])
	if err != nil {
		return Address{}, errors.New("pair: damaged — it was probably cut short or line-wrapped in transit")
	}

	var a Address
	if err := json.Unmarshal(raw, &a); err != nil {
		return Address{}, errors.New("pair: damaged — it was probably cut short or line-wrapped in transit")
	}
	if a.NodeKey.IsZero() || a.DiscoKey.IsZero() || !a.Addr.IsValid() {
		return Address{}, errors.New("pair: incomplete — ask for a fresh one from 'makima pair'")
	}
	return a, nil
}

// String renders the address, or a diagnostic if it cannot be rendered.
// Present so an Address can be printed without every caller handling an error
// that only a malformed value can produce.
func (a Address) String() string {
	s, err := Encode(a)
	if err != nil {
		return "<invalid pairing address: " + err.Error() + ">"
	}
	return s
}

// tokenDomain separates this hash from every other use of SHA-256 in makima,
// so a value computed here can never be replayed as one computed elsewhere.
const tokenDomain = "makima-pair-token-v1"

// Token is the proof a knocker includes to show it holds this address.
//
// Without a preshared key the real gate is the seal: a knock is encrypted to
// the disco key, which appears nowhere but in an address, so producing one
// that opens already demonstrates possession. The token is then a cheap,
// constant-time restatement of that.
//
// With a preshared key it becomes the point. The secret is folded in, so
// someone who learned the disco key by other means — a screenshot, a shoulder,
// a log — still cannot pair without the half that was never displayed.
func Token(a Address) []byte {
	h := sha256.New()
	h.Write([]byte(tokenDomain))
	nodeKey := a.NodeKey
	h.Write(nodeKey[:])
	discoKey := a.DiscoKey
	h.Write(discoKey[:])
	psk := a.PSK
	h.Write(psk[:])
	return h.Sum(nil)
}

// TokenValid reports whether a presented token matches this address.
func TokenValid(a Address, presented []byte) bool {
	return TokenEqual(Token(a), presented)
}

// TokenEqual compares two tokens in constant time.
//
// Exported because the machine checking a knock holds the token it expects,
// not the address it came from — it published that address and kept only the
// digest. Constant-time because a token is a secret: an attacker who can
// measure how long a comparison took can otherwise recover one byte at a time.
func TokenEqual(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// meshPrefix is the range every makima address comes from: RFC 6598 CGNAT
// space, the same one the control plane allocates out of.
var meshPrefix = netip.MustParsePrefix("100.64.0.0/10")

// MeshAddr derives a machine's mesh address from its node key.
//
// A serverless mesh has nobody to hand out addresses, so each machine takes
// one deterministically from the key it already has. Both ends compute the
// same answer from public information, which is what removes the negotiation
// step entirely.
//
// The /10 gives 22 usable host bits — four million addresses — so two of your
// own machines colliding is remote but not impossible, and a collision is
// detected and reported at pairing time rather than producing a mesh where two
// peers silently answer to the same address. The lowest address in the range
// is skipped because it reads as a network address and tends to be special-
// cased by tools that have no reason to.
func MeshAddr(k key.Public) netip.Addr {
	sum := sha256.Sum256(append([]byte("makima-pair-addr-v1"), k[:]...))

	// 22 bits of host space under 100.64.0.0/10.
	host := uint32(sum[0])<<16 | uint32(sum[1])<<8 | uint32(sum[2])
	host &= (1 << 22) - 1
	if host == 0 {
		host = 1
	}

	base := meshPrefix.Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v |= host

	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// InMesh reports whether an address falls in the range makima allocates from.
func InMesh(a netip.Addr) bool { return meshPrefix.Contains(a) }

// elide shortens a string for an error message, so a failed paste of something
// enormous does not fill the terminal with it.
func elide(s string) string {
	const max = 24
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
