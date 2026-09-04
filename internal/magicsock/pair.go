package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/justin06lee/makima/internal/disco"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/pair"
)

// Pairing is the serverless rendezvous: how two nodes with no control plane
// between them become peers.
//
// It rides on the disco socket rather than inventing a transport, because path
// discovery already had to solve the harder version of the same problem —
// getting a small authenticated message to a machine whose address nobody
// knows. A knock reaches its target the same way a probe does: through the
// relay when there is one, straight at a candidate endpoint when the two are
// on the same LAN, and both at once when it is not obvious which will work.

// knockInterval is how often an unanswered knock is repeated.
//
// Faster than the probe interval on purpose. A knock happens while somebody is
// watching a terminal waiting for it to land, and the burst is bounded by the
// caller's context rather than running forever.
const knockInterval = time.Second

// PairingSelf is what a node says about itself during a pairing.
//
// Deliberately small. This is everything a stranger learns by exchanging
// knocks: two public keys, the mesh address this machine will answer on, a
// name for it, and where it currently thinks it can be reached.
type PairingSelf struct {
	Addr      netip.Addr
	Name      string
	Endpoints []netip.AddrPort
}

// PairedPeer is what the far end said about itself, ready to be written into a
// configuration as a peer.
type PairedPeer struct {
	NodeKey   key.Public
	DiscoKey  key.Public
	Addr      netip.Addr
	Name      string
	Endpoints []netip.AddrPort
}

// Pairing is an open invitation to be knocked on.
//
// A node with no Pairing set answers no knocks at all — not with a refusal,
// with silence. That is the resting state, and it is why publishing a pairing
// address is not by itself dangerous: the address is only useful while its
// window is open.
type Pairing struct {
	// Token is what a knocker must present. It binds the pairing address —
	// including any preshared key in it — to the exchange.
	Token []byte

	// Self is what to tell an accepted knocker about this machine.
	Self PairingSelf

	// Until closes the window. A pairing that never expires is a listening
	// service somebody forgot about, so the caller must always name a moment
	// at which this stops.
	Until time.Time

	// Accept is called for each knock that verifies, off the packet path.
	// Returning an error refuses it silently; returning nil sends the
	// acknowledgement, so the far end only ever hears "yes" after this node
	// has genuinely configured it.
	Accept func(PairedPeer) error
}

// expired reports whether the window has closed.
func (p *Pairing) expired() bool { return time.Now().After(p.Until) }

// pending is one knock this node is waiting on an answer to.
type pending struct {
	once sync.Once
	done chan PairedPeer
}

// SetPairing opens or closes this node's pairing window. Nil closes it.
func (c *Conn) SetPairing(p *Pairing) {
	c.pairMu.Lock()
	c.pairing = p
	c.pairMu.Unlock()
}

// PairingOpen reports whether this node is currently accepting knocks.
func (c *Conn) PairingOpen() bool {
	_, ok := c.PairingExpiry()
	return ok
}

// PairingExpiry reports when the open pairing window closes, and whether one
// is open at all.
func (c *Conn) PairingExpiry() (time.Time, bool) {
	c.pairMu.Lock()
	defer c.pairMu.Unlock()
	if c.pairing == nil || c.pairing.expired() {
		return time.Time{}, false
	}
	return c.pairing.Until, true
}

// ErrPairingRefused reports a knock that went unanswered.
//
// One error for every reason, because the far end deliberately does not say
// which: a closed window, a wrong token and a machine that is not there are
// indistinguishable from the outside, and that is the intended property.
var ErrPairingRefused = errors.New("no answer")

// Knock asks the machine behind a pairing address to admit this node.
//
// It returns what the far end says about itself *now*, not what the address
// said when it was minted. An address may be minutes or days old and endpoints
// change constantly, so the acknowledgement is the first current thing in the
// exchange and is what the caller should configure from.
//
// If this node has no relay of its own and the address names one, that relay
// is adopted. A serverless node has no control plane to assign it one, and the
// only relay both ends are certain to agree on is the one in the address.
func (c *Conn) Knock(ctx context.Context, a pair.Address, self PairingSelf) (PairedPeer, error) {
	if a.NodeKey == c.nodeKey.Public() {
		return PairedPeer{}, errors.New("that is this machine's own pairing address")
	}

	if a.Relay != "" && c.RelayURL() == "" {
		c.setRelay(a.Relay, a.RelayKey)
	}

	// Prime the peer state so the knock — and the probing that follows it —
	// has somewhere to aim. This is the same shape SetNetwork builds from a
	// netmap; here the address plays the netmap's part.
	ps := c.peerFor(a.NodeKey)
	ps.mu.Lock()
	ps.discoKey = a.DiscoKey
	ps.candidates = append([]netip.AddrPort(nil), a.Endpoints...)
	ps.relayURL = a.Relay
	ps.mu.Unlock()

	c.mu.Lock()
	c.byDisco[a.DiscoKey] = ps
	for _, e := range a.Endpoints {
		c.byAddr[normalise(e)] = ps
	}
	c.mu.Unlock()

	tx, ok := newTxID()
	if !ok {
		return PairedPeer{}, errors.New("magicsock: no entropy for a pairing transaction")
	}

	p := &pending{done: make(chan PairedPeer, 1)}
	c.pairMu.Lock()
	if c.knocks == nil {
		c.knocks = make(map[disco.TxID]*pending)
	}
	c.knocks[tx] = p
	c.pairMu.Unlock()

	defer func() {
		c.pairMu.Lock()
		delete(c.knocks, tx)
		c.pairMu.Unlock()
	}()

	msg := &disco.Knock{
		TxID:      tx,
		NodeKey:   c.nodeKey.Public(),
		Addr:      self.Addr,
		Name:      self.Name,
		Token:     pair.Token(a),
		Endpoints: self.Endpoints,
	}
	pkt, err := disco.Seal(msg, a.DiscoKey, c.discoKey)
	if err != nil {
		return PairedPeer{}, fmt.Errorf("magicsock: seal knock: %w", err)
	}

	// Repeat until answered. The first knock through a relay routinely
	// arrives before the far end's relay session is up, and the first one over
	// UDP routinely opens a NAT mapping rather than reaching anybody.
	ticker := time.NewTicker(knockInterval)
	defer ticker.Stop()

	for {
		c.sendKnock(pkt, a)

		select {
		case peer := <-p.done:
			return peer, nil
		case <-ticker.C:
		case <-ctx.Done():
			return PairedPeer{}, ErrPairingRefused
		case <-c.closed:
			return PairedPeer{}, errors.New("magicsock: closed")
		}
	}
}

// sendKnock sprays one knock down every path the address suggests.
//
// Both at once rather than in sequence: which one works is exactly the
// question pairing cannot answer in advance, and a knock is one small packet.
func (c *Conn) sendKnock(pkt []byte, a pair.Address) {
	for _, e := range a.Endpoints {
		_ = c.sendUDP([][]byte{pkt}, e)
	}
	if a.Relay != "" {
		_ = c.sendRelay([][]byte{pkt}, a.NodeKey)
	}
}

// handleKnock processes an inbound request to pair.
//
// Reached only after the packet opened under this node's disco key, so the
// sender already holds an address of ours; the token check is what binds any
// preshared key in that address to this exchange.
func (c *Conn) handleKnock(sender key.Public, m *disco.Knock, src netip.AddrPort, relayed bool) {
	c.pairMu.Lock()
	p := c.pairing
	c.pairMu.Unlock()

	if p == nil || p.expired() {
		return
	}
	if !pair.TokenEqual(p.Token, m.Token) {
		// Silence, not a refusal. Answering would confirm that this machine
		// runs makima and is simply not accepting this particular caller.
		return
	}
	if m.NodeKey == c.nodeKey.Public() {
		return
	}

	peer := PairedPeer{
		NodeKey:   m.NodeKey,
		DiscoKey:  sender,
		Addr:      m.Addr,
		Name:      m.Name,
		Endpoints: append([]netip.AddrPort(nil), m.Endpoints...),
	}
	// A knock that arrived over UDP has proved something its own endpoint list
	// cannot: that this exact address reaches the sender right now. It is
	// worth more than the hints, so it goes first.
	if !relayed && src.IsValid() {
		peer.Endpoints = append([]netip.AddrPort{normalise(src)}, peer.Endpoints...)
	}

	// Off the packet path: accepting means writing a configuration file and
	// reconfiguring a WireGuard device, and the receive loop must not wait for
	// either. The acknowledgement follows acceptance rather than preceding it,
	// so "yes" always means the peer is already configured here.
	go func() {
		if err := p.Accept(peer); err != nil {
			c.log.Printf("pairing: refused %s: %v", shortKey(m.NodeKey), err)
			return
		}
		c.ackKnock(m.TxID, sender, m.NodeKey, p.Self, src, relayed)
	}()
}

// ackKnock answers an accepted knock along the path it arrived on.
func (c *Conn) ackKnock(tx disco.TxID, discoKey, nodeKey key.Public, self PairingSelf, src netip.AddrPort, relayed bool) {
	msg := &disco.Knocked{
		TxID:      tx,
		NodeKey:   c.nodeKey.Public(),
		Addr:      self.Addr,
		Name:      self.Name,
		Endpoints: self.Endpoints,
	}
	pkt, err := disco.Seal(msg, discoKey, c.discoKey)
	if err != nil {
		return
	}

	// Back the way it came, and — when that was the relay — also straight at
	// the endpoints the knock advertised. The relay answer is the one that is
	// certain to arrive; the direct ones are what start the hole punch.
	if relayed {
		_ = c.sendRelay([][]byte{pkt}, nodeKey)
	} else if src.IsValid() {
		_ = c.sendUDP([][]byte{pkt}, src)
	}
}

// handleKnocked completes a pairing this node started.
func (c *Conn) handleKnocked(sender key.Public, m *disco.Knocked, src netip.AddrPort, relayed bool) {
	c.pairMu.Lock()
	p := c.knocks[m.TxID]
	c.pairMu.Unlock()

	if p == nil {
		// No transaction waiting. Either a duplicate of one already completed,
		// or an answer to a knock somebody else sent; neither is actionable.
		return
	}

	peer := PairedPeer{
		NodeKey:   m.NodeKey,
		DiscoKey:  sender,
		Addr:      m.Addr,
		Name:      m.Name,
		Endpoints: append([]netip.AddrPort(nil), m.Endpoints...),
	}
	if !relayed && src.IsValid() {
		peer.Endpoints = append([]netip.AddrPort{normalise(src)}, peer.Endpoints...)
	}

	// once, because the knock is repeated until answered and every repeat can
	// draw its own acknowledgement.
	p.once.Do(func() { p.done <- peer })
}
