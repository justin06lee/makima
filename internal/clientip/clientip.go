// Package clientip finds the address a request really came from when a
// reverse proxy stands in front of the server.
//
// The control plane and the relay it carries each rate-limit by the address
// a request arrives from, which is right when nodes connect to them directly.
// Behind a reverse proxy or a Cloudflare tunnel — a setup the README
// documents — every request arrives from the proxy, so every node shared one
// budget: a fleet restarting at once locked most of itself out, and one noisy
// client anywhere on the internet could spend the budget for everybody.
//
// A proxy says who it is forwarding for in X-Forwarded-For. That header is
// believed only from a proxy that is trusted to set it — by default one on
// this machine — because anybody else can write whatever they like in it,
// and a header that is always believed is a fresh budget per request. Only
// X-Forwarded-For is read, not Forwarded: a proxy that sets one commonly
// passes the other through from the client untouched, and reading both would
// let the client choose.
package clientip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// Proxies are the addresses trusted to say, in X-Forwarded-For, whom they
// are forwarding for.
type Proxies []netip.Prefix

// Loopback trusts a proxy on this machine and nothing else: cloudflared, or
// a Caddy or nginx beside the server. Anything on this machine could reach
// the server directly anyway, so believing what it says costs nothing.
var Loopback = Proxies{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// Parse reads a comma-separated list of addresses and prefixes. An empty
// string trusts nobody.
func Parse(s string) (Proxies, error) {
	var out Proxies
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			// Addresses are compared unmapped, so a prefix written in
			// IPv4-mapped form is kept as the IPv4 prefix it names.
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q is neither an address nor a prefix", f)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// String renders the list the way Parse reads it.
func (p Proxies) String() string {
	parts := make([]string, len(p))
	for i, x := range p {
		parts[i] = x.String()
	}
	return strings.Join(parts, ",")
}

func (p Proxies) trusts(a netip.Addr) bool {
	a = a.Unmap()
	for _, x := range p {
		if x.Contains(a) {
			return true
		}
	}
	return false
}

// Of is the address a request came from: remoteAddr, the peer that
// connected, unless that peer is a trusted proxy — then the nearest address
// in X-Forwarded-For that is not one.
//
// The header is read from the right, because each proxy appends the
// address it was reached from, and whatever the client itself wrote is on
// the left: a trusted proxy's entry can be believed, and the one before it
// is only as good as the proxy that wrote it. So the walk goes left past
// trusted proxies and stops at the first address that is not one. An entry
// that does not parse stops it too, at the last address that could be
// believed, so a mangled header shares the proxy's budget rather than
// buying a fresh one.
//
// The result is a host with no port, or remoteAddr as given if it names no
// address at all.
func (p Proxies) Of(remoteAddr string, h http.Header) string {
	peer, ok := parseHost(remoteAddr)
	if !ok {
		return remoteAddr
	}
	if !p.trusts(peer) {
		return peer.String()
	}

	var hops []string
	for _, v := range h.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseHost(strings.TrimSpace(hops[i]))
		if !ok {
			break
		}
		peer = a
		if !p.trusts(a) {
			break
		}
	}
	return peer.String()
}

// parseHost reads an address with or without a port, IPv6 bracketed or not,
// as one address per host: unmapped, and without an IPv6 zone.
//
// With a port is tried first. The other order read "[fe80::1%en0]:50001",
// brackets trimmed, as an address whose zone was "en0]:50001" — port and
// all, so every connection from one link-local host counted as a new one.
func parseHost(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}
