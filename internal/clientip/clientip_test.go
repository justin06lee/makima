package clientip

import (
	"net/http"
	"testing"
)

func header(xff ...string) http.Header {
	h := http.Header{}
	for _, v := range xff {
		h.Add("X-Forwarded-For", v)
	}
	return h
}

// Behind a proxy on this machine, the client is who the proxy says it is.
// Before, every node behind one proxy shared one rate-limit budget.
func TestAProxyOnThisMachineIsBelieved(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		h      http.Header
		want   string
	}{
		{"cloudflared", "127.0.0.1:51234", header("198.51.100.7"), "198.51.100.7"},
		{"ipv6 loopback", "[::1]:51234", header("2001:db8::7"), "2001:db8::7"},
		{"mapped loopback", "[::ffff:127.0.0.1]:51234", header("198.51.100.7"), "198.51.100.7"},
		{"with a port", "127.0.0.1:51234", header("198.51.100.7:40000"), "198.51.100.7"},
		{"bracketed ipv6", "127.0.0.1:51234", header("[2001:db8::7]"), "2001:db8::7"},
		{"no header", "127.0.0.1:51234", header(), "127.0.0.1"},
	}
	for _, c := range cases {
		if got := Loopback.Of(c.remote, c.h); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// Anybody can write the header. From a peer that is not a trusted proxy it
// is ignored, or every request could name a new address and get a fresh
// budget.
func TestTheHeaderIsIgnoredFromAnyoneElse(t *testing.T) {
	if got := Loopback.Of("203.0.113.9:40000", header("198.51.100.7")); got != "203.0.113.9" {
		t.Errorf("a direct client's header was believed: %q", got)
	}
	if got := (Proxies{}).Of("127.0.0.1:40000", header("198.51.100.7")); got != "127.0.0.1" {
		t.Errorf("with no proxy trusted, the header was believed: %q", got)
	}
}

// Each proxy appends the address it was reached from; whatever the client
// wrote is on the left. Reading from the right, past trusted proxies only,
// is what stops the client choosing.
func TestTheClientCannotChooseItsOwnAddress(t *testing.T) {
	// nginx's $proxy_add_x_forwarded_for keeps what the client sent and
	// appends the real peer.
	got := Loopback.Of("127.0.0.1:51234", header("10.9.9.9, 198.51.100.7"))
	if got != "198.51.100.7" {
		t.Errorf("%q, want the address the proxy saw, 198.51.100.7", got)
	}

	// Two trusted proxies in a row: the walk goes past both.
	p, err := Parse("127.0.0.0/8, 192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	got = p.Of("127.0.0.1:51234", header("10.9.9.9, 198.51.100.7", "192.0.2.10"))
	if got != "198.51.100.7" {
		t.Errorf("through two trusted proxies: %q, want 198.51.100.7", got)
	}
}

// A mangled entry is not a fresh budget: the walk stops at the last address
// it could believe.
func TestAMangledHeaderSharesTheProxysBudget(t *testing.T) {
	if got := Loopback.Of("127.0.0.1:51234", header("not an address")); got != "127.0.0.1" {
		t.Errorf("%q, want the proxy's own address", got)
	}
	if got := Loopback.Of("127.0.0.1:51234", header("198.51.100.7, junk")); got != "127.0.0.1" {
		t.Errorf("%q: the walk went past an entry it could not read", got)
	}
}

func TestParse(t *testing.T) {
	p, err := Parse(" 10.0.0.0/8 ,192.0.2.1,, ::1 ")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.String(); got != "10.0.0.0/8,192.0.2.1/32,::1/128" {
		t.Errorf("parsed %q", got)
	}
	if p, err := Parse(""); err != nil || len(p) != 0 {
		t.Errorf("an empty list: %v, %v", p, err)
	}
	if _, err := Parse("example.com"); err == nil {
		t.Error("a name was taken for an address")
	}
}

// A peer on a link-local address arrives as "[fe80::1%en0]:50001". Reading
// the zone as running to the end of the string kept the port in the result,
// so every connection from one host got a budget of its own.
func TestAZonedPeerIsOneAddressWhateverItsPort(t *testing.T) {
	a := Loopback.Of("[fe80::1%en0]:50001", header())
	b := Loopback.Of("[fe80::1%en0]:50002", header())
	if a != b {
		t.Errorf("one host counted as two: %q and %q", a, b)
	}
	if a != "fe80::1" {
		t.Errorf("%q, want fe80::1", a)
	}
}

// A trusted prefix written in IPv4-mapped form names the IPv4 addresses it
// covers; addresses are compared unmapped, so it has to be too.
func TestAMappedPrefixIsTrustedAsIPv4(t *testing.T) {
	p, err := Parse("::ffff:192.0.2.0/120")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Of("192.0.2.10:40000", header("198.51.100.7")); got != "198.51.100.7" {
		t.Errorf("a proxy inside a mapped prefix was not trusted: %q", got)
	}
}
