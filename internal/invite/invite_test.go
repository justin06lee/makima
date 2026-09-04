package invite

import (
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

func sample(t *testing.T) Invite {
	t.Helper()
	priv, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	return Invite{
		Server:    "http://control.example:8080",
		AuthKey:   "makima_abc123",
		ServerKey: priv.Public(),
	}
}

func TestRoundTrip(t *testing.T) {
	in := sample(t)
	in.Expires = time.Now().Add(time.Hour).Truncate(time.Second)

	s, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, Prefix) {
		t.Fatalf("encoded invite %q has no prefix", s)
	}

	out, err := Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	if out.Server != in.Server || out.AuthKey != in.AuthKey || out.ServerKey != in.ServerKey {
		t.Fatalf("round trip changed the invite:\n got %+v\nwant %+v", out, in)
	}
	if !out.Expires.Equal(in.Expires) {
		t.Fatalf("expiry: got %v want %v", out.Expires, in.Expires)
	}
}

// The point of the format: one string, so an invite cannot be pasted without
// the server key that makes it safe.
func TestEncodeRefusesIncomplete(t *testing.T) {
	full := sample(t)

	for _, tc := range []struct {
		name string
		mut  func(*Invite)
	}{
		{"no server", func(i *Invite) { i.Server = "" }},
		{"no auth key", func(i *Invite) { i.AuthKey = "" }},
		{"no server key", func(i *Invite) { i.ServerKey = key.Public{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := full
			tc.mut(&inv)
			if _, err := Encode(inv); err == nil {
				t.Fatal("encoded an invite that cannot be joined with")
			}
		})
	}
}

// An invite survives the trip through a chat window and a shell.
func TestDecodeTolerance(t *testing.T) {
	s, err := Encode(sample(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		given string
	}{
		{"clean", s},
		{"leading and trailing space", "  " + s + "\n"},
		{"double quoted", `"` + s + `"`},
		{"single quoted", "'" + s + "'"},
		{"prefix typed in caps", strings.ToUpper(Prefix) + strings.TrimPrefix(s, Prefix)},
		// An email client that hard-wraps at 72 columns has not damaged
		// anything — every byte is still there, and base64 skips the breaks.
		// Truncation is the failure worth catching, and that one still fails.
		{"line wrapped", s[:20] + "\n" + s[20:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.given); err != nil {
				t.Fatalf("Decode(%q): %v", tc.given, err)
			}
		})
	}
}

// A truncated invite has to fail, not half-work: a join that proceeds with a
// mangled server key is exactly the failure the bundle exists to prevent.
func TestDecodeRejectsDamage(t *testing.T) {
	s, err := Encode(sample(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		given string
	}{
		{"empty", ""},
		{"not an invite", "hello"},
		{"prefix only", Prefix},
		{"truncated", s[:len(s)-12]},
		{"wrong prefix", "tsnet_" + strings.TrimPrefix(s, Prefix)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.given); err == nil {
				t.Fatalf("Decode(%q) accepted a damaged invite", tc.given)
			}
		})
	}
}

func TestExpired(t *testing.T) {
	inv := sample(t)
	if inv.Expired() {
		t.Fatal("an invite with no expiry has expired")
	}
	inv.Expires = time.Now().Add(-time.Minute)
	if !inv.Expired() {
		t.Fatal("a lapsed invite reports itself valid")
	}
	inv.Expires = time.Now().Add(time.Minute)
	if inv.Expired() {
		t.Fatal("a live invite reports itself expired")
	}
}

// Two invites minted from the same details are still distinguishable, so
// nobody has to wonder whether they pasted the stale one.
func TestEncodeIsUnique(t *testing.T) {
	in := sample(t)
	a, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two mintings produced the same string")
	}
}

// The error for a mispaste names the thing that was wrong without printing an
// entire novel back at the terminal.
func TestDecodeErrorIsShort(t *testing.T) {
	_, err := Decode(strings.Repeat("x", 4000))
	if err == nil {
		t.Fatal("accepted 4000 characters of nonsense")
	}
	if len(err.Error()) > 120 {
		t.Fatalf("error is %d characters long:\n%s", len(err.Error()), err)
	}
}
