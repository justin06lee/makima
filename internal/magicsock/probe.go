package magicsock

import (
	"crypto/rand"
	"net/netip"
	"time"

	"github.com/justin06lee/makima/internal/disco"
	"github.com/justin06lee/makima/internal/key"
)

// probeInterval is how often an unproven peer is probed, and how often a
// proven one is refreshed.
//
// Five seconds is a compromise between two failure modes. Slower, and a NAT
// mapping opened by an outbound probe can lapse before the reply arrives, so a
// path that would have worked is never found. Faster, and a mesh of any size
// spends a noticeable slice of its wakeups on probes that will almost always
// say the same thing.
const probeInterval = 5 * time.Second

// probeTimeout is how long a transaction stays open. Anything slower than this
// is not a path worth having, and keeping the record alive only lets a
// duplicate reply reset a timer it should not.
const probeTimeout = 3 * time.Second

// probeBurst caps how many addresses are probed for one peer at once.
//
// A node with many interfaces — several VPNs, a container bridge, a couple of
// physical NICs — can advertise a long candidate list, and probing all of them
// on every tick turns discovery into a small packet flood. Ten covers any
// plausible real machine.
const probeBurst = 10

// isDiscoPacket is the receive path's classifier, kept here so the wire format
// stays entirely inside package disco.
func isDiscoPacket(b []byte) bool { return disco.IsDiscoPacket(b) }

// probeLoop drives path discovery for every peer.
//
// One goroutine for the whole socket rather than one per peer: probing is a
// timer-driven sweep, and a single ticker walking the peer map keeps the cost
// proportional to the mesh rather than to the number of goroutines Go is
// willing to create.
func (c *Conn) probeLoop() {
	t := time.NewTicker(probeInterval)
	defer t.Stop()

	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			c.probeAll()
		}
	}
}

func (c *Conn) probeAll() {
	c.mu.RLock()
	states := make([]*peerState, 0, len(c.peers))
	for _, ps := range c.peers {
		states = append(states, ps)
	}
	c.mu.RUnlock()

	for _, ps := range states {
		c.probePeer(ps, false)
	}
}

// maybeProbe triggers a probe outside the normal tick, rate-limited so a burst
// of traffic to an unreachable peer cannot turn into a burst of probes.
func (c *Conn) maybeProbe(ps *peerState) {
	ps.mu.Lock()
	recent := time.Since(ps.lastProbeAt) < probeInterval
	ps.mu.Unlock()
	if recent {
		return
	}
	go c.probePeer(ps, false)
}

// probePeer sends a disco ping to every candidate path for one peer.
//
// A peer with a healthy direct path is still probed, at the same interval:
// that is what keeps the path's trust window from lapsing, and it is how a
// path that has silently broken — the far side rebooted, the NAT rebalanced —
// is noticed within seconds instead of on the next data packet.
func (c *Conn) probePeer(ps *peerState, force bool) {
	ps.mu.Lock()

	if ps.discoKey.IsZero() {
		// Nothing to seal a probe to. The peer is either running a version
		// without disco or has not registered yet; the relay carries it.
		ps.mu.Unlock()
		return
	}

	if !force {
		if addr, ok := ps.directPathLocked(); ok && time.Since(ps.bestAt) < probeInterval {
			// Heard from recently on a good path; nothing to establish.
			_ = addr
			ps.mu.Unlock()
			return
		}
	}

	targets := append([]netip.AddrPort(nil), ps.candidates...)
	if ps.best.IsValid() {
		targets = appendUnique(targets, ps.best)
	}
	discoKey := ps.discoKey
	relayed := ps.relayURL != ""
	ps.lastProbeAt = time.Now()

	c.expireProbesLocked(ps)
	ps.mu.Unlock()

	if len(targets) > probeBurst {
		targets = targets[:probeBurst]
	}

	for _, addr := range targets {
		c.sendPing(ps, discoKey, addr)
	}

	// A peer we have no candidate addresses for is not hopeless: a ping over
	// the relay reaches it wherever it is, and its pong reports the address our
	// probe appeared to come from — which is how two nodes that have never met
	// learn each other's public addresses without a STUN server in the middle.
	if relayed {
		c.sendPingRelayed(ps, discoKey)
	}
}

// newTxID mints a transaction ID.
//
// Falling back to a timestamp on an entropy failure would be worse than
// useless — predictable transaction IDs let an off-path attacker forge a pong
// and steer a peer onto an address of their choosing — so a failure here
// simply skips the probe.
func newTxID() (disco.TxID, bool) {
	var tx disco.TxID
	if _, err := rand.Read(tx[:]); err != nil {
		return tx, false
	}
	return tx, true
}

func (c *Conn) sendPing(ps *peerState, discoKey key.Public, addr netip.AddrPort) {
	tx, ok := newTxID()
	if !ok {
		return
	}

	pkt, err := disco.Seal(&disco.Ping{TxID: tx, NodeKey: c.nodeKey.Public()}, discoKey, c.discoKey)
	if err != nil {
		return
	}

	ps.mu.Lock()
	ps.probes[tx] = &probe{addr: addr, sent: time.Now()}
	ps.mu.Unlock()

	_ = c.sendUDP([][]byte{pkt}, addr)
}

// sendPingRelayed sends a probe through the relay rather than to an address.
//
// The transaction is recorded with no address, because what comes back tells
// us where *we* appear to be, not that any particular path works.
func (c *Conn) sendPingRelayed(ps *peerState, discoKey key.Public) {
	tx, ok := newTxID()
	if !ok {
		return
	}

	pkt, err := disco.Seal(&disco.Ping{TxID: tx, NodeKey: c.nodeKey.Public()}, discoKey, c.discoKey)
	if err != nil {
		return
	}

	ps.mu.Lock()
	ps.probes[tx] = &probe{sent: time.Now()}
	ps.mu.Unlock()

	_ = c.sendRelay([][]byte{pkt}, ps.nodeKey)
}

// expireProbesLocked drops transactions that will never be answered. Callers
// must hold ps.mu.
func (c *Conn) expireProbesLocked(ps *peerState) {
	for tx, p := range ps.probes {
		if time.Since(p.sent) > probeTimeout {
			delete(ps.probes, tx)
		}
	}
}

// handleDisco processes a disco packet that arrived over UDP.
func (c *Conn) handleDisco(b []byte, src netip.AddrPort) {
	sender, msg, err := disco.Open(b, c.discoKey)
	if err != nil {
		// Unopenable means it was not for us, or was forged. Either way there
		// is nothing to say about it, and saying anything would confirm to a
		// prober that this address runs makima.
		return
	}

	// Pairing is handled before the peer lookup, and is the only thing that
	// is: a knock comes from a machine that is by definition not a peer yet,
	// so requiring one would make serverless pairing impossible.
	switch m := msg.(type) {
	case *disco.Knock:
		c.handleKnock(sender, m, src, false)
		return
	case *disco.Knocked:
		c.handleKnocked(sender, m, src, false)
		return
	}

	c.mu.RLock()
	ps := c.byDisco[sender]
	c.mu.RUnlock()
	if ps == nil {
		// A valid probe from a key the control plane has not told us about.
		// Refusing it is what keeps a stranger who has somehow obtained a
		// disco key from installing themselves as a path.
		return
	}

	switch m := msg.(type) {
	case *disco.Ping:
		c.handlePing(ps, m, src, false)
	case *disco.Pong:
		c.handlePong(ps, m, src)
	}
}

// handleDiscoRelayed processes a disco packet that arrived through the relay.
//
// The relay path is the rendezvous: it is how a ping reaches a peer whose
// address is unknown, and the pong it triggers is what teaches both ends where
// to aim their direct probes.
func (c *Conn) handleDiscoRelayed(b []byte, srcNode key.Public) {
	sender, msg, err := disco.Open(b, c.discoKey)
	if err != nil {
		return
	}

	switch m := msg.(type) {
	case *disco.Knock:
		// The relay's header names the sender, and only a connection that
		// proved possession of that node key could have set it. A knock
		// claiming a different one inside is lying about half of itself.
		if m.NodeKey != srcNode {
			return
		}
		c.handleKnock(sender, m, netip.AddrPort{}, true)
		return
	case *disco.Knocked:
		if m.NodeKey != srcNode {
			return
		}
		c.handleKnocked(sender, m, netip.AddrPort{}, true)
		return
	}

	c.mu.RLock()
	ps := c.byDisco[sender]
	c.mu.RUnlock()
	if ps == nil || ps.nodeKey != srcNode {
		// The disco key and the relay's node key must agree. They come from
		// two independent sources — the netmap and the relay's authenticated
		// handshake — so a mismatch means one of them is lying.
		return
	}

	switch m := msg.(type) {
	case *disco.Ping:
		c.handlePing(ps, m, netip.AddrPort{}, true)
	case *disco.Pong:
		c.handlePong(ps, m, netip.AddrPort{})
	}
}

// handlePing answers a probe and treats it as an invitation to probe back.
//
// Answering alone is not enough to open a path through two NATs. Both ends
// have to send outbound, near-simultaneously, so that each one's NAT has a
// mapping waiting when the other's packet arrives. A received ping is the best
// possible signal that the far end is trying right now, so the reply is
// immediately followed by our own probe — that symmetry is the hole punch.
func (c *Conn) handlePing(ps *peerState, p *disco.Ping, src netip.AddrPort, relayed bool) {
	ps.mu.Lock()
	discoKey := ps.discoKey
	// Bind the disco key to the node key it claims, but only when the control
	// plane has not already said otherwise: the netmap is authoritative, and a
	// ping must not be able to re-point an existing peer.
	mismatch := ps.nodeKey != p.NodeKey
	ps.mu.Unlock()

	if mismatch {
		return
	}

	pong, err := disco.Seal(&disco.Pong{TxID: p.TxID, Src: src}, discoKey, c.discoKey)
	if err != nil {
		return
	}

	if relayed {
		_ = c.sendRelay([][]byte{pong}, ps.nodeKey)
	} else {
		_ = c.sendUDP([][]byte{pong}, src)
		// The ping proved this address reaches us. That is half the evidence
		// needed; the pong we get back for our own probe is the other half.
		ps.noteDirectRecv(src)
	}

	c.maybeProbe(ps)
}

// handlePong closes a transaction, promoting the path it validates.
func (c *Conn) handlePong(ps *peerState, p *disco.Pong, src netip.AddrPort) {
	ps.mu.Lock()

	pr, ok := ps.probes[p.TxID]
	if !ok {
		// Unknown transaction: either it timed out, or someone is guessing.
		// Twelve random bytes make guessing hopeless, which is exactly why the
		// transaction ID is checked before anything is believed.
		ps.mu.Unlock()
		return
	}
	delete(ps.probes, p.TxID)

	rtt := time.Since(pr.sent)
	ps.mu.Unlock()

	// Report where the peer saw our probe coming from. Over a relayed probe
	// this is our public address as observed by a peer — free STUN, from a
	// party that already has reason to talk to us.
	if p.Src.IsValid() {
		c.noteSelfObservation(normalise(p.Src))
	}

	if !src.IsValid() {
		// A relayed pong confirms the peer is alive and reachable through the
		// relay, but says nothing about any direct path.
		return
	}

	ps.mu.Lock()
	// Smoothed rather than replaced, so one scheduling hiccup does not make a
	// good path look bad and trigger a switch.
	if ps.latency == 0 {
		ps.latency = rtt
	} else {
		ps.latency = (ps.latency*3 + rtt) / 4
	}

	// Prefer a materially faster path. The margin stops two comparable paths
	// from flapping, which would reset WireGuard's endpoint on every tick.
	switchTo := !ps.best.IsValid() || ps.best == src || time.Since(ps.bestAt) > directTrust
	if !switchTo && rtt*2 < ps.latency {
		switchTo = true
	}
	ps.mu.Unlock()

	if switchTo {
		ps.noteDirectRecv(src)
		c.learnAddr(src, ps)
	}
}

// learnAddr records that a peer is reachable at an address, so a later data
// packet from it can be attributed without another probe.
func (c *Conn) learnAddr(addr netip.AddrPort, ps *peerState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byAddr[normalise(addr)] = ps
}
