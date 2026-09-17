package sshd

import (
	"net/netip"
	"testing"

	"golang.org/x/crypto/ssh"
)

// line builds one authorized_keys line with options in front of a real key.
func line(t *testing.T, opts string) []byte {
	t.Helper()
	key := ssh.MarshalAuthorizedKey(pubOf(t))
	if opts == "" {
		return key
	}
	return append([]byte(opts+" "), key...)
}

// A line that grants one command is not a line that grants a shell. Reading
// only the key half of it and starting a shell is the bug this guards.
func TestALineThatForcesACommandDoesNotOpenAnAccount(t *testing.T) {
	for _, opts := range []string{
		`command="/usr/bin/backup"`,
		`restrict,command="/usr/bin/backup"`,
		`command="rsync --server",no-pty`,
	} {
		keys, err := ParseAuthorizedKeys(line(t, opts))
		if err == nil && len(keys) != 0 {
			t.Errorf("%s was honoured as a login key", opts)
		}
	}
}

// Options nobody here has examined are refusals, not permissions.
func TestAnUnknownOptionMakesALineUnusable(t *testing.T) {
	for _, opts := range []string{
		"cert-authority",
		`principals="admin"`,
		`expiry-time="20260101"`,
		"verify-required",
		"something-invented-later",
	} {
		keys, err := ParseAuthorizedKeys(line(t, opts))
		if err == nil && len(keys) != 0 {
			t.Errorf("%s was honoured", opts)
		}
	}
}

// The ones that ask for something this server never does anyway are harmless.
func TestOptionsThisServerNeverHonoursAnywayAreIgnored(t *testing.T) {
	opts := "no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc"
	keys, err := ParseAuthorizedKeys(line(t, opts))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("parsed %d keys, want 1", len(keys))
	}
	if !keys[0].PTY {
		t.Error("a line with only forwarding options lost its terminal")
	}
}

func TestNoPTYAndRestrictTakeTheTerminalAway(t *testing.T) {
	for _, opts := range []string{"no-pty", "restrict"} {
		keys, err := ParseAuthorizedKeys(line(t, opts))
		if err != nil {
			t.Fatalf("%s: %v", opts, err)
		}
		if len(keys) != 1 {
			t.Fatalf("%s: parsed %d keys", opts, len(keys))
		}
		if keys[0].PTY {
			t.Errorf("%s still allowed a terminal", opts)
		}
	}

	// And pty after restrict puts it back, as OpenSSH reads it.
	keys, err := ParseAuthorizedKeys(line(t, "restrict,pty"))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys[0].PTY {
		t.Error("restrict,pty did not allow a terminal")
	}
}

// The move from Tailscale writes exactly this line, so it has to keep working.
func TestTheMovesTemporaryKeyLineIsHonoured(t *testing.T) {
	opts := `from="10.77.0.0/16",no-agent-forwarding,no-port-forwarding,no-X11-forwarding`
	keys, err := ParseAuthorizedKeys(line(t, opts))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("parsed %d keys, want 1", len(keys))
	}
	if !keys[0].Allows(netip.MustParseAddr("10.77.0.5")) {
		t.Error("a mesh address was refused by from=10.77.0.0/16")
	}
	if keys[0].Allows(netip.MustParseAddr("192.168.1.5")) {
		t.Error("a LAN address was admitted by from=10.77.0.0/16")
	}
}

func TestFromPatterns(t *testing.T) {
	cases := []struct {
		from   string
		remote string
		want   bool
	}{
		{"", "10.77.0.5", true},
		{`from="10.77.0.0/16"`, "10.77.0.5", true},
		{`from="10.77.0.0/16"`, "10.78.0.5", false},
		{`from="10.77.0.5"`, "10.77.0.5", true},
		{`from="10.77.0.5"`, "10.77.0.6", false},
		{`from="*"`, "10.77.0.5", true},
		{`from="10.77.0.*"`, "10.77.0.5", true},
		{`from="10.77.0.*"`, "10.77.1.5", false},
		{`from="10.77.0.0/16,192.168.1.0/24"`, "192.168.1.5", true},

		// A negated pattern refuses outright, whatever else matched.
		{`from="10.77.0.0/16,!10.77.0.5"`, "10.77.0.5", false},
		{`from="10.77.0.0/16,!10.77.0.5"`, "10.77.0.6", true},

		// IPv6, and a mesh address written the long way.
		{`from="fd7a::/16"`, "fd7a::1", true},
		{`from="fd7a::/16"`, "fe80::1", false},

		// A name pattern is not resolved, so it matches nothing.
		{`from="*.example.com"`, "10.77.0.5", false},
	}

	for _, c := range cases {
		keys, err := ParseAuthorizedKeys(line(t, c.from))
		if err != nil || len(keys) != 1 {
			t.Fatalf("%s did not parse: %v", c.from, err)
		}
		if got := keys[0].Allows(netip.MustParseAddr(c.remote)); got != c.want {
			t.Errorf("%s from %s = %v, want %v", c.from, c.remote, got, c.want)
		}
	}
}

// An address that could not be read is not one any from= line admits.
func TestFromRefusesAnUnknownAddress(t *testing.T) {
	keys, err := ParseAuthorizedKeys(line(t, `from="10.77.0.0/16"`))
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].Allows(netip.Addr{}) {
		t.Error("an unknown address satisfied from=")
	}
}

func TestUnquoteStripsOnlyTheOuterQuotes(t *testing.T) {
	for in, want := range map[string]string{
		`"10.0.0.1"`: "10.0.0.1",
		`10.0.0.1`:   "10.0.0.1",
		`"a\"b"`:     `a"b`,
		`""`:         "",
		` "spaced" `: "spaced",
	} {
		if got := unquote(in); got != want {
			t.Errorf("unquote(%s) = %q, want %q", in, got, want)
		}
	}
}
