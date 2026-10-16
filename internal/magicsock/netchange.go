package magicsock

import (
	"net/netip"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// NetworkChanged tells the socket the machine's own network moved: a laptop
// that left the house, a Wi-Fi that handed out a new address.
//
// Everything the socket had learned went through the old network. A confirmed
// direct path to a peer on the home LAN is a path to nowhere from a café, and
// left alone it keeps being trusted — and every packet sent down it alone —
// for the rest of its trust window, which is most of a minute of silence. The
// addresses peers saw us at belong to the old network's NAT. And the relay is
// a TCP connection from an address the machine no longer has, which the
// kernel may take minutes to declare dead.
//
// So all of it is dropped: every peer goes back to "try every candidate and
// the relay at once", which is what makes the first packets after a move get
// through on whatever path still works, and probing starts over at once to
// find a direct one again.
func (c *Conn) NetworkChanged() {
	states := c.peerStates()
	for _, ps := range states {
		ps.mu.Lock()
		ps.best = netip.AddrPort{}
		ps.bestAt = time.Time{}
		ps.latency = 0
		ps.lastProbeAt = time.Time{}
		ps.mu.Unlock()
	}
	c.forgetSelf()
	c.RedialRelay()
	c.probeNow(states)
}

// LinkBack tells the socket the machine's link dropped and came back on the
// network it left: a Wi-Fi drop, a roam between access points, the same
// addresses again.
//
// Nothing learned went stale. The peers are where they were, the router's
// mapping for this machine is the one it had, and the relay connection — to
// tor's port on this machine, or across a LAN that is still there — may well
// have outlived the drop. Throwing all of that away, as NetworkChanged does,
// is what made every drop on a machine with flaky Wi-Fi a reconnection from
// scratch. All this does is ask every peer at once whether the path in use
// still works, which re-proves it, or finds the one that does, within a
// round trip.
func (c *Conn) LinkBack() {
	c.probeNow(c.peerStates())
}

// Renumbered tells the socket the machine is on the network it was on, but
// no longer holds an address it had: a DHCP server that handed out another
// one, most often.
//
// The paths are kept — the peers have not moved — but stop being trusted on
// their own, so packets go down every candidate and the relay until a probe
// proves a path again: this end sends from somewhere new now, and a far end
// whose NAT only lets in what it has seen will drop it until it has. What
// this machine was observed at is forgotten, since that was the router's
// mapping for the old address, and the relay, connected from the old
// address, is dialled again.
func (c *Conn) Renumbered() {
	states := c.peerStates()
	for _, ps := range states {
		ps.mu.Lock()
		ps.bestAt = time.Time{}
		ps.lastProbeAt = time.Time{}
		ps.mu.Unlock()
	}
	c.forgetSelf()
	c.RedialRelay()
	c.probeNow(states)
}

func (c *Conn) peerStates() []*peerState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	states := make([]*peerState, 0, len(c.peers))
	for _, ps := range c.peers {
		states = append(states, ps)
	}
	return states
}

// forgetSelf drops the addresses this machine was observed at, and with them
// the reason not to ask a STUN server again.
func (c *Conn) forgetSelf() {
	c.selfMu.Lock()
	c.observed = nil
	c.peerSawPublic = time.Time{}
	c.selfMu.Unlock()
}

// probeNow probes every peer in states without waiting for the next tick.
func (c *Conn) probeNow(states []*peerState) {
	for _, ps := range states {
		go c.probePeer(ps, true)
	}
}

// RedialRelay replaces the relay connection with a fresh one: after the
// socket binding changed, the old connection is going out the wrong way.
func (c *Conn) RedialRelay() {
	c.mu.RLock()
	url, relayKey := c.relayURL, c.relayKey
	c.mu.RUnlock()
	if url != "" {
		c.redialRelay(url, relayKey)
	}
}

// redialRelay dials url afresh. setRelay keeps a connection to the same URL;
// clearing the URL first is what makes it dial a fresh one.
func (c *Conn) redialRelay(url string, relayKey key.Public) {
	c.mu.Lock()
	c.relayURL = ""
	c.mu.Unlock()
	c.setRelay(url, relayKey)
}
