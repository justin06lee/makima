// Package ddns keeps a DuckDNS name pointed at this machine's public address.
//
// A home connection's public address changes now and then — a router reboot,
// the ISP's whim — and every machine that knew the control plane by it would
// lose it at once. A name that is kept current is how they find it again:
// the control plane updates the name, and a node that can no longer reach the
// old address looks the name up and reaches the new one.
//
// DuckDNS because it is free, needs no domain, and its whole API is one GET.
// Its account token is the only credential, shown on its page after signing
// in.
package ddns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Endpoint is DuckDNS's update URL. A variable so tests can stand one up.
var Endpoint = "https://www.duckdns.org/update"

// Suffix is what every DuckDNS name ends in.
const Suffix = ".duckdns.org"

// Every is how often the name is refreshed. DuckDNS asks for no more than
// every five minutes, and an address change is noticed within one interval.
const Every = 5 * time.Minute

// Result is what an update reported.
type Result struct {
	// IP is the address DuckDNS now holds for the name.
	IP string

	// Changed is true when this update moved the name, false when it already
	// pointed there.
	Changed bool
}

// ErrRefused is DuckDNS saying no: the name is not this token's, or the token
// is wrong. Worth telling apart from a network failure, because retrying it
// will never help.
var ErrRefused = errors.New("DuckDNS refused the update — check the name is one you created, and the token is the one on your DuckDNS page")

// Update points name at the public IPv4 address this request comes from.
//
// The address is left for DuckDNS to see rather than worked out here: the
// request leaves through the same router every other connection does, so
// what DuckDNS sees is exactly the address the world reaches this machine at.
// That is why the request is made over IPv4 only — an update that happened to
// go out over IPv6 would be seen from an address the name is not meant for.
func Update(ctx context.Context, name, token string) (Result, error) {
	if name == "" || token == "" {
		return Result{}, errors.New("ddns: a name and a token are both needed")
	}

	q := url.Values{
		"domains": {name},
		"token":   {token},
		"ip":      {""},
		"verbose": {"true"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, Endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return Result{}, err
	}

	resp, err := ipv4Client().Do(req)
	if err != nil {
		// The URL carries the token, and net/http puts the URL in its errors.
		return Result{}, fmt.Errorf("reach DuckDNS: %w", redact(err, token))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return Result{}, fmt.Errorf("read DuckDNS's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("DuckDNS answered %s", resp.Status)
	}
	return parse(string(body))
}

// parse reads a verbose answer: OK, the IPv4 address, the IPv6 address, and
// UPDATED or NOCHANGE, one per line. A bare KO is a refusal.
func parse(body string) (Result, error) {
	lines := strings.Split(strings.TrimSpace(body), "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	switch lines[0] {
	case "OK":
	case "KO":
		return Result{}, ErrRefused
	default:
		return Result{}, fmt.Errorf("DuckDNS answered something unexpected: %q", body)
	}

	var r Result
	if len(lines) > 1 {
		r.IP = lines[1]
	}
	r.Changed = lines[len(lines)-1] == "UPDATED"
	return r, nil
}

// Name turns what somebody typed into the bare DuckDNS subdomain: "tenet",
// "tenet.duckdns.org" and "https://tenet.duckdns.org/" are all "tenet".
func Name(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimRight(s, "/")
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.TrimSuffix(s, Suffix)
	if !validName.MatchString(s) {
		return "", fmt.Errorf("%q is not a DuckDNS name — it is the part before %s, letters, digits and dashes", raw, Suffix)
	}
	return s, nil
}

var validName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// Host is the full name a DuckDNS subdomain answers to.
func Host(name string) string { return name + Suffix }

func ipv4Client() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	d := &net.Dialer{Timeout: 10 * time.Second}
	t.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp4", addr)
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: t}
}

// redact keeps a credential out of an error that is about to be logged.
func redact(err error, secret string) error {
	if secret == "" || !strings.Contains(err.Error(), secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "REDACTED"))
}
