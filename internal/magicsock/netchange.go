package magicsock

import (
	"net/netip"
	"time"
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
	c.mu.RLock()
	states := make([]*peerState, 0, len(c.peers))
	for _, ps := range c.peers {
		states = append(states, ps)
	}
	url, relayKey := c.relayURL, c.relayKey
	c.mu.RUnlock()

	for _, ps := range states {
		ps.mu.Lock()
		ps.best = netip.AddrPort{}
		ps.bestAt = time.Time{}
		ps.latency = 0
		ps.lastProbeAt = time.Time{}
		ps.mu.Unlock()
	}

	c.selfMu.Lock()
	c.observed = nil
	c.peerSawPublic = time.Time{}
	c.selfMu.Unlock()

	if url != "" {
		// setRelay keeps a connection to the same URL; clearing the URL
		// first is what makes it dial a fresh one.
		c.mu.Lock()
		c.relayURL = ""
		c.mu.Unlock()
		c.setRelay(url, relayKey)
	}

	for _, ps := range states {
		go c.probePeer(ps, true)
	}
}
