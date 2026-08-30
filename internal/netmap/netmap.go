// Package netmap holds the mesh's view of itself.
//
// A NetMap answers one question for one node: who am I, and who may I talk to?
// Everything else in makima exists to produce or consume this type.
//
// It is deliberately the same struct whether it was read from a static file
// (M0) or long-polled from the control server (M1). The daemon renders a
// NetMap into a live WireGuard configuration and does not care which produced
// it, so growing a control plane never touches the data path.
package netmap

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/wg"
)

// keepalive is sent to every peer regardless of traffic.
//
// This is not just a NAT nicety. Most consumer NATs drop an idle UDP mapping
// somewhere between 30 and 180 seconds, and once the mapping is gone the peer
// that did not speak last becomes unreachable until it transmits. 25 seconds
// stays comfortably under the worst common timeout.
const keepalive = 25 * time.Second

// NodeID is the control plane's stable handle for a node. It survives key
// rotation, which is the whole reason a node is not simply identified by its
// public key.
type NodeID uint64

// Node is one machine in the mesh, as seen by everyone else.
type Node struct {
	ID   NodeID     `json:"id"`
	Name string     `json:"name"`
	Key  key.Public `json:"key"`

	// DiscoKey authenticates this node's path probes. Peers need it before
	// they can probe: a probe sealed to the wrong key is indistinguishable
	// from noise, which is exactly the property that keeps strangers out.
	DiscoKey key.Public `json:"disco_key,omitzero"`

	// Addresses are the node's own mesh IPs, always inside the CGNAT range.
	Addresses []netip.Prefix `json:"addresses"`

	// AllowedIPs are additional prefixes this node routes on behalf of others
	// — the subnet-router case. Empty for an ordinary laptop.
	AllowedIPs []netip.Prefix `json:"allowed_ips,omitempty"`

	// Endpoints are candidate paths to reach this node: LAN addresses, a
	// STUN-observed public address, a port-mapped address. In a static mesh
	// these are written by hand; in a managed one the node gathers them itself
	// and republishes on every poll.
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`

	// RelayURL is where this node can always be reached, even when no direct
	// path exists. Empty means the node has no relay and is only reachable
	// directly.
	RelayURL string `json:"relay_url,omitempty"`

	// Online is the control plane's view of whether the node is currently
	// polling. Advisory: a node can be reachable without having polled
	// recently, and unreachable despite having done so.
	Online bool `json:"online,omitempty"`

	// KeySignature is the network-lock signature over this node's key, empty
	// when the mesh has no lock enabled. Verified by every peer before the
	// node is admitted to the data plane, which is what stops a compromised
	// control server from introducing one.
	KeySignature []byte `json:"key_signature,omitempty"`

	// Services are the ports this node publishes on the mesh.
	//
	// Advertised so the rest of the mesh can answer "what can I reach from
	// here?" without anyone maintaining a list by hand. Only the mesh-facing
	// port is published, never where it forwards to: a peer has no use for
	// the knowledge that a service lives on 127.0.0.1:11434, and publishing
	// internal layout for no benefit is how a convenience becomes a
	// reconnaissance aid.
	Services []Service `json:"services,omitempty"`
}

// Service is one port a node publishes on the mesh.
type Service struct {
	Name string `json:"name,omitempty"`
	Port uint16 `json:"port"`

	// Scheme is a hint for building a URL, "http" or "https" when the service
	// speaks it. Empty means a plain TCP port and nothing to link to.
	Scheme string `json:"scheme,omitempty"`
}

// URL renders a clickable address for a service on a node, or empty when the
// service is not something a browser can open.
func (s Service) URL(host string) string {
	if s.Scheme == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s:%d", s.Scheme, host, s.Port)
}

// GuessScheme reports the scheme a port most likely speaks.
//
// A guess, and only ever used to decide whether to render a link. Getting it
// wrong costs a browser tab; not guessing at all costs the entire point of
// publishing a web service on a mesh, which is that you can click it.
func GuessScheme(port uint16) string {
	switch port {
	case 80, 3000, 5000, 7860, 8000, 8080, 8081, 8188, 8888, 11434:
		return "http"
	case 443, 8443:
		return "https"
	}
	return ""
}

// Relay is a relay a node may use.
type Relay struct {
	URL string     `json:"url"`
	Key key.Public `json:"key,omitzero"`
}

// NetMap is one node's complete picture of the mesh.
type NetMap struct {
	// PrivateKey is local-only and never crosses the wire. It lives here
	// because rendering a WireGuard config needs it alongside the peers, and
	// splitting it out only invites the two drifting apart.
	PrivateKey key.Private `json:"private_key"`

	Self  Node   `json:"self"`
	Peers []Node `json:"peers"`

	// ListenPort is the local UDP port WireGuard binds. Zero asks the kernel
	// to choose, which is the right default once disco can discover and
	// publish whatever it picked.
	ListenPort uint16 `json:"listen_port"`

	// HomeRelay is the relay this node connects to and advertises as its own.
	// Peers reach it there when no direct path works.
	HomeRelay Relay `json:"home_relay,omitzero"`

	// DNS is the mesh's name service configuration.
	DNS DNSConfig `json:"dns,omitzero"`

	// Domain is the mesh's DNS suffix, e.g. "makima".
	Domain string `json:"domain,omitempty"`
}

// DNSConfig is what a node needs to answer mesh name lookups.
type DNSConfig struct {
	// Enabled turns on the local resolver and the OS integration that points
	// mesh names at it.
	Enabled bool `json:"enabled,omitempty"`

	// Domain is the suffix mesh names live under.
	Domain string `json:"domain,omitempty"`

	// Nameservers are upstream resolvers for names outside the mesh, used only
	// when this node is acting as an exit node's DNS.
	Nameservers []netip.Addr `json:"nameservers,omitempty"`
}

// Addr is the node's primary mesh address.
func (n Node) Addr() (netip.Addr, error) {
	if len(n.Addresses) == 0 {
		return netip.Addr{}, fmt.Errorf("node %q has no mesh address", n.Name)
	}
	return n.Addresses[0].Addr(), nil
}

// WireGuardConfig renders the map into the data plane's desired state.
//
// A peer's AllowedIPs is the union of the addresses it owns and any subnet it
// routes: in WireGuard that single field is both the routing table and the
// authorisation check, since a packet arriving from a peer is dropped unless
// its source falls inside that peer's AllowedIPs. Cryptokey routing does the
// work an ACL would otherwise have to.
func (m *NetMap) WireGuardConfig() wg.Config {
	cfg := wg.Config{
		PrivateKey: m.PrivateKey,
		ListenPort: m.ListenPort,
		Peers:      make([]wg.Peer, 0, len(m.Peers)),
	}

	for _, p := range m.Peers {
		allowed := make([]netip.Prefix, 0, len(p.Addresses)+len(p.AllowedIPs))
		allowed = append(allowed, p.Addresses...)
		allowed = append(allowed, p.AllowedIPs...)

		peer := wg.Peer{
			PublicKey:  p.Key,
			AllowedIPs: allowed,
			Keepalive:  keepalive,
		}
		if len(p.Endpoints) > 0 {
			ep := p.Endpoints[0]
			peer.Endpoint = &ep
		}
		cfg.Peers = append(cfg.Peers, peer)
	}
	return cfg
}

// Routes are the prefixes the host should send down the tunnel.
//
// Deliberately not simply the whole CGNAT range: routing all of 100.64.0.0/10
// into the tunnel would blackhole traffic to mesh addresses that are not
// actually in this node's map, which matters as soon as ACLs start trimming
// who can see whom.
//
// An exit node's default-route halves are excluded even though they arrive as
// ordinary AllowedIPs. Installing them here would redirect this machine's
// entire default route the moment any peer became an exit node — including for
// nodes that never asked to use one — and would do it without the pinned route
// that keeps the exit node itself reachable. Using an exit node is an opt-in
// with a careful installation order, and that lives in netcfg.
func (m *NetMap) Routes() []netip.Prefix {
	var routes []netip.Prefix
	for _, p := range m.Peers {
		routes = append(routes, p.Addresses...)
		for _, r := range p.AllowedIPs {
			if IsDefaultHalf(r) {
				continue
			}
			routes = append(routes, r)
		}
	}
	return routes
}

// DefaultHalves are the two prefixes that together mean "all IPv4 traffic".
//
// Expressed as halves rather than 0.0.0.0/0 so they win over the host's real
// default route by longest-prefix match while leaving it intact underneath —
// which makes undoing an exit node a matter of removing two routes rather than
// reconstructing the original default from memory.
var DefaultHalves = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
}

// IsDefaultHalf reports whether a prefix is one of them.
func IsDefaultHalf(p netip.Prefix) bool {
	for _, h := range DefaultHalves {
		if p == h {
			return true
		}
	}
	return false
}

// OffersExit reports whether a node has been approved as an exit node.
func (n Node) OffersExit() bool {
	found := 0
	for _, r := range n.AllowedIPs {
		if IsDefaultHalf(r) {
			found++
		}
	}
	return found == len(DefaultHalves)
}
