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

	// Addresses are the node's own mesh IPs, always inside the CGNAT range.
	Addresses []netip.Prefix `json:"addresses"`

	// AllowedIPs are additional prefixes this node routes on behalf of others
	// — the subnet-router case. Empty for an ordinary laptop.
	AllowedIPs []netip.Prefix `json:"allowed_ips,omitempty"`

	// Endpoints are candidate paths to reach this node: LAN addresses, a
	// STUN-observed public address, a port-mapped address. In M0 these are
	// written by hand. From M3 disco discovers and ranks them, and the first
	// entry is simply the current best guess.
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`
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
func (m *NetMap) Routes() []netip.Prefix {
	var routes []netip.Prefix
	for _, p := range m.Peers {
		routes = append(routes, p.Addresses...)
		routes = append(routes, p.AllowedIPs...)
	}
	return routes
}
