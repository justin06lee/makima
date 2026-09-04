package key

import (
	"strings"
	"testing"
)

func TestPrivateRoundTrip(t *testing.T) {
	priv, err := NewPrivate()
	if err != nil {
		t.Fatalf("NewPrivate: %v", err)
	}
	got, err := ParsePrivate(priv.Base64())
	if err != nil {
		t.Fatalf("ParsePrivate: %v", err)
	}
	if got != priv {
		t.Error("private key did not survive a base64 round trip")
	}
}

// A key must derive the same public half every time, including after being
// written to disk and read back. If clamping were applied inconsistently the
// two would silently diverge and every peer would reject the handshake.
func TestClampIsStable(t *testing.T) {
	priv, err := NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := ParsePrivate(priv.Base64())
	if err != nil {
		t.Fatal(err)
	}
	if priv.Public() != reparsed.Public() {
		t.Error("public key changed across a round trip; clamping is not idempotent")
	}
}

func TestClampedBits(t *testing.T) {
	priv, err := NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	if priv[0]&7 != 0 {
		t.Errorf("low three bits not cleared: %08b", priv[0])
	}
	if priv[31]&128 != 0 {
		t.Errorf("high bit not cleared: %08b", priv[31])
	}
	if priv[31]&64 == 0 {
		t.Errorf("second-highest bit not set: %08b", priv[31])
	}
}

func TestKeysAreDistinct(t *testing.T) {
	a, _ := NewPrivate()
	b, _ := NewPrivate()
	if a == b {
		t.Fatal("two generated keys were identical")
	}
	if a.Public() == b.Public() {
		t.Fatal("two distinct keys derived the same public half")
	}
}

func TestParseRejectsJunk(t *testing.T) {
	for _, s := range []string{
		"",                    // empty
		"not base64 at all!!", // undecodable
		"c2hvcnQ=",            // decodes, wrong length
	} {
		if _, err := ParsePublic(s); err == nil {
			t.Errorf("ParsePublic(%q) accepted a bad key", s)
		}
	}
}

// The private key's String must never leak the secret, because it is what
// fmt and every logging call reach for by default.
func TestPrivateStringRedacts(t *testing.T) {
	priv, err := NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(priv.String(), priv.Base64()) {
		t.Error("String() leaked the private key")
	}
}

func TestPublicTextMarshal(t *testing.T) {
	priv, _ := NewPrivate()
	pub := priv.Public()

	b, err := pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var got Public
	if err := got.UnmarshalText(b); err != nil {
		t.Fatal(err)
	}
	if got != pub {
		t.Error("public key did not survive text marshalling")
	}
}

func TestSharedRoundTrip(t *testing.T) {
	s, err := NewShared()
	if err != nil {
		t.Fatal(err)
	}
	if s.IsZero() {
		t.Fatal("a freshly generated preshared key is all zeroes")
	}

	back, err := ParseShared(s.Base64())
	if err != nil {
		t.Fatal(err)
	}
	if back != s {
		t.Error("preshared key did not survive base64 round trip")
	}

	// The hex form is what reaches wireguard-go, so it has to be the same 32
	// bytes and nothing else.
	if len(s.Hex()) != Size*2 {
		t.Errorf("hex form is %d characters, want %d", len(s.Hex()), Size*2)
	}
}

// The zero Shared is how "no preshared key" is spelled, so it must never be
// mistaken for a real one.
func TestSharedZeroIsNone(t *testing.T) {
	var s Shared
	if !s.IsZero() {
		t.Error("the zero preshared key does not report itself as unset")
	}
}

func TestSharedStringRedacts(t *testing.T) {
	s, err := NewShared()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.String(), s.Base64()) {
		t.Errorf("String() leaked the secret: %q", s.String())
	}
}

func TestSharedTextMarshal(t *testing.T) {
	s, err := NewShared()
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	var back Shared
	if err := back.UnmarshalText(b); err != nil {
		t.Fatal(err)
	}
	if back != s {
		t.Error("preshared key did not survive a text round trip")
	}
}
