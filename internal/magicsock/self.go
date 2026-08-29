package magicsock

import (
	"net/netip"
	"sort"
	"time"
)

// observationTTL is how long an address this node was observed at is still
// advertised.
//
// A public address behind NAT is only as durable as the mapping that created
// it, and a laptop that changes networks invalidates every one of them at
// once. Expiring them means a stale address stops being advertised on its own
// rather than persisting until something explicitly notices the move.
const observationTTL = 5 * time.Minute

// selfObservation is an address some other party reported seeing us at.
type selfObservation struct {
	addr netip.AddrPort
	at   time.Time

	// confirmations counts how many distinct sources agreed on this address.
	// One peer reporting an address could be mistaken or lying; several
	// agreeing is what makes it worth advertising to the whole mesh.
	confirmations int
}

// noteSelfObservation records an address a peer or a STUN server saw us at.
//
// This is the outward half of discovery: the local interface list says where
// this machine thinks it is, and these say where the rest of the world thinks
// it is. The difference between the two is precisely what NAT did, and the
// union is the candidate set peers get to probe.
func (c *Conn) noteSelfObservation(addr netip.AddrPort) {
	if !addr.IsValid() || addr.Port() == 0 {
		return
	}
	// An address inside the mesh range would mean a peer saw us through
	// another tunnel. Advertising it tells peers to reach us through a tunnel
	// to reach a tunnel.
	if isMeshAddr(addr.Addr()) {
		return
	}

	c.selfMu.Lock()
	defer c.selfMu.Unlock()

	now := time.Now()
	for i := range c.observed {
		if c.observed[i].addr == addr {
			c.observed[i].at = now
			c.observed[i].confirmations++
			return
		}
	}
	c.observed = append(c.observed, selfObservation{addr: addr, at: now, confirmations: 1})
	c.log.Printf("magicsock: observed self at %s", addr)
}

// SelfEndpoints returns the addresses this node should advertise, newest and
// best-confirmed first.
//
// The caller unions this with the local interface addresses; between them they
// cover the LAN case (local addresses, no NAT in the way) and the internet case
// (observed addresses, which only exist because something answered).
func (c *Conn) SelfEndpoints() []netip.AddrPort {
	c.selfMu.Lock()
	defer c.selfMu.Unlock()

	live := c.observed[:0]
	for _, o := range c.observed {
		if time.Since(o.at) < observationTTL {
			live = append(live, o)
		}
	}
	c.observed = live

	// Stable ordering, so an unchanged set does not look like a change to the
	// control server and bump the netmap version on every poll. Sorting by
	// confirmations first puts the address most parties agree on at the front,
	// which is the one a peer should try first.
	//
	// The observations are sorted rather than the extracted addresses: sorting
	// two slices in lockstep by indexing one from the other's comparator is a
	// reliable way to produce garbage once the swaps begin.
	sort.Slice(live, func(i, j int) bool {
		if live[i].confirmations != live[j].confirmations {
			return live[i].confirmations > live[j].confirmations
		}
		return live[i].addr.String() < live[j].addr.String()
	})

	out := make([]netip.AddrPort, 0, len(live))
	for _, o := range live {
		out = append(out, o.addr)
	}
	return out
}

// isMeshAddr reports whether an address is inside the CGNAT range makima and
// Tailscale both allocate from.
//
// Duplicated from netcfg rather than imported, because netcfg shells out to
// platform tools and magicsock must stay usable in a unit test.
func isMeshAddr(a netip.Addr) bool {
	return meshRange.Contains(a)
}

var meshRange = netip.MustParsePrefix("100.64.0.0/10")
