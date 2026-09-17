package sshd

import (
	"net/netip"
	"strings"

	"golang.org/x/crypto/ssh"
)

// AuthorizedKey is one line of an authorized_keys file: a key, and whatever
// that line said may be done with it.
//
// The options matter as much as the key. A line like
//
//	command="/usr/bin/backup",restrict ssh-ed25519 AAAA...
//
// is not permission to log in — it is permission to run one program. Reading
// only the key half of such a line and handing out a shell is the difference
// between honouring an authorized_keys file and merely glancing at it.
type AuthorizedKey struct {
	Key ssh.PublicKey

	// From is the from="..." patterns, empty when the line has none.
	From []string

	// PTY is false when the line said no-pty or restrict.
	PTY bool
}

// Grant is what a key that opened an account may do once it is in.
type Grant struct {
	// PTY allows an interactive terminal. Without it a session still runs a
	// command, which is what no-pty means everywhere else.
	PTY bool
}

// ignorableOptions are the ones that ask for something makima's server never
// does anyway. Honouring them is a no-op, so a key carrying them is still a
// key that may log in.
//
// Deliberately an allowlist. An option nobody here has thought about is far
// more likely to be a restriction than a permission — that is what options in
// this file are for — so anything unrecognised makes the line unusable rather
// than usable in some unexamined way.
var ignorableOptions = map[string]bool{
	"no-port-forwarding":  true,
	"no-agent-forwarding": true,
	"no-x11-forwarding":   true,
	"no-user-rc":          true,
	"port-forwarding":     true,
	"agent-forwarding":    true,
	"x11-forwarding":      true,
	"user-rc":             true,
	"permitopen":          true,
	"permitlisten":        true,
	"tunnel":              true,
	"environment":         true,
	"no-touch-required":   true,
}

// parseOptions turns one line's options into an AuthorizedKey, reporting
// whether the line may be used for a login at all.
//
// False for the options that mean something this server cannot honour:
//
//	command=         the line grants one program, not a shell
//	cert-authority   the key signs certificates rather than logging in
//	principals=      only meaningful with cert-authority
//	expiry-time=     a deadline this server does not track
//	verify-required  a hardware check this server does not make
//
// In every one of those cases the safe reading is that the key does not open
// this account here — the system's own sshd, which does implement them, is
// still free to accept it.
func parseOptions(opts []string, key ssh.PublicKey) (AuthorizedKey, bool) {
	a := AuthorizedKey{Key: key, PTY: true}

	for _, opt := range opts {
		name, value, hasValue := strings.Cut(opt, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		value = unquote(value)

		switch name {
		case "":
			continue
		case "no-pty":
			a.PTY = false
		case "restrict":
			// Everything off, then anything later in the line back on.
			a.PTY = false
		case "pty":
			a.PTY = true
		case "from":
			if !hasValue || value == "" {
				return AuthorizedKey{}, false
			}
			a.From = append(a.From, splitPatterns(value)...)
		default:
			if !ignorableOptions[name] {
				return AuthorizedKey{}, false
			}
		}
	}
	return a, true
}

// unquote strips the quotes an authorized_keys option value carries, and the
// backslash escapes inside them.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return strings.ReplaceAll(s, `\"`, `"`)
}

// splitPatterns splits a comma-separated from= list.
func splitPatterns(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Allows reports whether this line admits a connection from remote.
//
// OpenSSH's from= semantics: a negated pattern that matches refuses outright,
// and otherwise at least one positive pattern has to match. A line with no
// from= admits anybody who holds the key — which, on a server bound to a mesh
// address, is already anybody who reached it.
//
// Name patterns (from="*.example.com") are refused rather than resolved. They
// would need a reverse lookup whose answer comes from the network, and a
// permission decided by a PTR record is not a permission.
func (a AuthorizedKey) Allows(remote netip.Addr) bool {
	if len(a.From) == 0 {
		return true
	}
	if !remote.IsValid() {
		return false
	}

	matched := false
	for _, p := range a.From {
		negated := strings.HasPrefix(p, "!")
		pattern := strings.TrimPrefix(p, "!")

		if !patternMatches(pattern, remote) {
			continue
		}
		if negated {
			return false
		}
		matched = true
	}
	return matched
}

// patternMatches matches one from= pattern against an address.
func patternMatches(pattern string, remote netip.Addr) bool {
	if pattern == "*" {
		return true
	}
	if prefix, err := netip.ParsePrefix(pattern); err == nil {
		return prefix.Contains(remote.Unmap())
	}
	if addr, err := netip.ParseAddr(pattern); err == nil {
		return addr.Unmap() == remote.Unmap()
	}
	// A glob over the address as text, which is how OpenSSH reads a pattern
	// that is neither a CIDR nor an address — but only over something that
	// looks like an address, never a hostname.
	if strings.ContainsAny(pattern, "*?") && isAddressShaped(pattern) {
		return globMatch(pattern, remote.Unmap().String())
	}
	return false
}

// isAddressShaped keeps a glob to the characters addresses are made of, so
// "*.example.com" is not quietly treated as one.
func isAddressShaped(p string) bool {
	for _, r := range p {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		case r == '.', r == ':', r == '*', r == '?', r == '/':
		default:
			return false
		}
	}
	return true
}

// globMatch is shell-style * and ? matching, the two wildcards authorized_keys
// patterns use. path.Match is not it: that one refuses to let * cross a '.',
// which is exactly what an address pattern needs it to do.
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	if pattern[0] == '*' {
		for i := 0; i <= len(s); i++ {
			if globMatch(pattern[1:], s[i:]) {
				return true
			}
		}
		return false
	}
	if s == "" {
		return false
	}
	if pattern[0] == '?' || pattern[0] == s[0] {
		return globMatch(pattern[1:], s[1:])
	}
	return false
}
