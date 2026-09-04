// Package invite turns everything a machine needs in order to join a mesh
// into one string you can paste.
//
// Joining used to take three flags — the server's URL, a credential, and the
// server's public key — and the third one was optional, which meant it was
// usually omitted. Omitting it is worse than it looks: without the key in
// hand, a joining node fetches it over the very connection it is about to
// trust, and nothing in that exchange can tell an impostor from the real
// server. The safe form was the long one, so people did the unsafe thing.
//
// Bundling all three removes the choice. There is one string, it always
// carries the key, and the shortest path is now also the correct one. The
// encoding is not a security measure and is not pretending to be one: an
// invite is a bearer credential, and anyone holding it can join. It is opaque
// only so that it survives being pasted into a chat window without a URL
// parser mangling it, and so that a truncated one fails loudly rather than
// half-working.
package invite

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// Prefix marks a string as an invite.
//
// Present so that a human can recognise one in a scrollback, and so that
// pasting the wrong thing entirely produces "that is not an invite" rather
// than a base64 error from three functions deeper.
const Prefix = "mk1_"

// Invite is everything a machine needs to join, and nothing else.
type Invite struct {
	// Server is the control plane's URL, as the joining machine must reach it.
	Server string `json:"s"`

	// AuthKey admits the machine. A bearer credential: whoever holds it joins.
	AuthKey string `json:"a"`

	// ServerKey is the control plane's public key.
	//
	// Carried so the joining node never has to ask the network who the server
	// is. This is the whole reason the bundle exists.
	ServerKey key.Public `json:"k"`

	// Expires is when the credential stops working, zero if it never does.
	// Advisory: the control plane enforces it. Carried so the CLI can say
	// "this invite expired an hour ago" instead of "join failed".
	Expires time.Time `json:"e,omitempty"`

	// Nonce makes two invites minted for the same mesh in the same second
	// differ, so nobody has to wonder whether they pasted a stale one.
	Nonce string `json:"n,omitempty"`
}

// Encode renders an invite as the single string a person pastes.
func Encode(inv Invite) (string, error) {
	if inv.Server == "" {
		return "", errors.New("invite: no server URL")
	}
	if inv.AuthKey == "" {
		return "", errors.New("invite: no auth key")
	}
	if inv.ServerKey.IsZero() {
		return "", errors.New("invite: no server key")
	}

	if inv.Nonce == "" {
		var b [6]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("invite: read entropy: %w", err)
		}
		inv.Nonce = base64.RawURLEncoding.EncodeToString(b[:])
	}

	payload, err := json.Marshal(inv)
	if err != nil {
		return "", fmt.Errorf("invite: encode: %w", err)
	}
	// Unpadded URL-safe base64: no "=" for a chat client to swallow, no "+"
	// or "/" for a URL to reinterpret, and it double-clicks as one word.
	return Prefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

// Decode parses a pasted invite.
//
// Tolerant of the ways a string arrives after a round trip through a human:
// surrounding whitespace, a shell's quotes, and the prefix having been typed
// in a different case.
func Decode(s string) (Invite, error) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	s = strings.TrimSpace(s)

	if s == "" {
		return Invite{}, errors.New("invite: empty")
	}
	if len(s) <= len(Prefix) || !strings.EqualFold(s[:len(Prefix)], Prefix) {
		return Invite{}, fmt.Errorf("invite: %q is not an invite (they start with %s)", elide(s), Prefix)
	}

	raw, err := base64.RawURLEncoding.DecodeString(s[len(Prefix):])
	if err != nil {
		return Invite{}, errors.New("invite: damaged — it was probably cut short or line-wrapped in transit")
	}

	var inv Invite
	if err := json.Unmarshal(raw, &inv); err != nil {
		return Invite{}, errors.New("invite: damaged — it was probably cut short or line-wrapped in transit")
	}
	if inv.Server == "" || inv.AuthKey == "" || inv.ServerKey.IsZero() {
		return Invite{}, errors.New("invite: incomplete — mint a fresh one with 'makima invite'")
	}
	return inv, nil
}

// Expired reports whether the credential inside has already lapsed.
func (i Invite) Expired() bool {
	return !i.Expires.IsZero() && time.Now().After(i.Expires)
}

// elide shortens a string for an error message, so a failed paste of something
// enormous does not fill the terminal with it.
func elide(s string) string {
	const max = 24
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
