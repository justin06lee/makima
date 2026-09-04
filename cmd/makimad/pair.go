package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/magicsock"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/pair"
)

// Serverless pairing, from the daemon's side.
//
// Everything here exists so that two machines can become peers with nothing
// between them: no control plane, no account, no membership. One side opens a
// window and publishes an address, the other knocks on it, and each writes the
// answer into its own configuration. The result is an ordinary makima mesh —
// the same WireGuard device, the same path selection, the same firewall — that
// simply nobody administers.

// errNotServerless reports pairing attempted on a node that has a control
// plane. The two are alternatives, not layers.
var errNotServerless = errors.New("this machine belongs to a mesh with a control server; add machines with 'makima invite' instead")

// openPairing publishes a pairing address and starts accepting knocks on it.
func (n *node) openPairing(ttl time.Duration) (string, time.Time, error) {
	if n.sock == nil {
		return "", time.Time{}, errNotServerless
	}
	if ttl <= 0 {
		ttl = pair.DefaultWindow
	}

	a, self, err := n.pairAddress()
	if err != nil {
		return "", time.Time{}, err
	}

	encoded, err := pair.Encode(a)
	if err != nil {
		// The one error that actually happens here: no relay configured and
		// no endpoint discovered yet, which is a real state on a machine whose
		// first STUN query has not come back.
		return "", time.Time{}, fmt.Errorf("%w — this machine has no address anyone could reach it at yet; try again in a moment, or give it a relay with 'makima up -relay HOST:PORT'", err)
	}

	until := time.Now().Add(ttl)
	n.sock.SetPairing(&magicsock.Pairing{
		Token:  pair.Token(a),
		Self:   self,
		Until:  until,
		Accept: n.acceptPaired,
	})

	log.Printf("pairing: open for %s", ttl.Round(time.Second))
	return encoded, until, nil
}

// pairAddressString renders the current pairing address and when the open
// window closes, for status. It does not open or extend anything.
func (n *node) pairAddressString() (string, time.Time, error) {
	until, open := n.sock.PairingExpiry()
	if !open {
		return "", time.Time{}, errors.New("no pairing window is open")
	}

	a, _, err := n.pairAddress()
	if err != nil {
		return "", time.Time{}, err
	}
	encoded, err := pair.Encode(a)
	if err != nil {
		return "", time.Time{}, err
	}
	return encoded, until, nil
}

// closePairing stops accepting knocks.
func (n *node) closePairing() {
	if n.sock != nil {
		n.sock.SetPairing(nil)
		log.Print("pairing: closed")
	}
}

// pairAddress builds this machine's current pairing address.
//
// Recomputed on every call rather than cached, because two of its fields — the
// endpoints and the relay — change underneath it. An address handed out five
// minutes ago may already name somewhere this machine no longer is.
func (n *node) pairAddress() (pair.Address, magicsock.PairingSelf, error) {
	n.mu.Lock()
	f := n.file
	name := f.Self.Name
	relay := f.HomeRelay
	nodeKey := f.NodeKey.Public()
	discoKey := f.DiscoKey.Public()
	addr, addrErr := f.Self.Addr()
	n.mu.Unlock()

	if addrErr != nil {
		// A serverless node derives its address from its own key, so this only
		// happens on a config that was never initialised for pairing.
		addr = pair.MeshAddr(nodeKey)
	}

	eps := n.endpoints()

	a := pair.Address{
		NodeKey:   nodeKey,
		DiscoKey:  discoKey,
		Addr:      addr,
		Name:      name,
		Relay:     relay.URL,
		RelayKey:  relay.Key,
		Endpoints: eps,
	}
	self := magicsock.PairingSelf{Addr: addr, Name: name, Endpoints: eps}
	return a, self, nil
}

// knock pairs with a machine that published an address.
func (n *node) knock(ctx context.Context, encoded string) (netmap.Node, error) {
	if n.sock == nil {
		return netmap.Node{}, errNotServerless
	}

	a, err := pair.Decode(encoded)
	if err != nil {
		return netmap.Node{}, err
	}

	_, self, err := n.pairAddress()
	if err != nil {
		return netmap.Node{}, err
	}

	peer, err := n.sock.Knock(ctx, a, self)
	if err != nil {
		return netmap.Node{}, fmt.Errorf("%w from %s — is 'makima pair' running there, and still inside its window?", err, describeMeetingPoint(a))
	}

	// The far end confirmed before answering, so by the time this returns it
	// already has us. Recording it here is what makes the pairing mutual.
	if err := n.acceptPaired(peer); err != nil {
		return netmap.Node{}, err
	}

	n.mu.Lock()
	node, _ := n.file.PairedPeer(peer.NodeKey)
	n.mu.Unlock()

	// The relay may have been adopted from the address during the knock, in
	// which case it is now this node's home relay and belongs in the config.
	n.adoptRelay(a)
	return node, nil
}

// describeMeetingPoint renders where a knock was aimed, for an error message.
func describeMeetingPoint(a pair.Address) string {
	switch {
	case a.Relay != "" && len(a.Endpoints) > 0:
		return fmt.Sprintf("%s (relay %s)", a.Endpoints[0], a.Relay)
	case a.Relay != "":
		return "relay " + a.Relay
	case len(a.Endpoints) > 0:
		return a.Endpoints[0].String()
	}
	return "that address"
}

// adoptRelay records a relay taken from a pairing address.
//
// magicsock adopts it live during the knock so the exchange can complete; this
// is what makes it survive a restart. Only when this node had none: a relay
// already in the configuration was chosen deliberately and is not overridden
// by whoever we happened to pair with.
func (n *node) adoptRelay(a pair.Address) {
	if a.Relay == "" {
		return
	}

	n.mu.Lock()
	if n.file.HomeRelay.URL != "" {
		n.mu.Unlock()
		return
	}
	n.file.HomeRelay = netmap.Relay{URL: a.Relay, Key: a.RelayKey}
	err := conf.Save(n.cfgPath, n.file)
	n.mu.Unlock()

	if err != nil {
		log.Printf("warning: could not record the relay from the pairing: %v", err)
		return
	}
	log.Printf("pairing: adopted relay %s", a.Relay)
}

// acceptPaired writes a newly paired machine into the configuration and brings
// it onto the data plane.
//
// Idempotent by node key, because a knock is repeated until it is answered and
// every repeat can arrive. Re-pairing an existing peer updates it in place,
// which is also how a machine that changed address or name is refreshed.
func (n *node) acceptPaired(p magicsock.PairedPeer) error {
	if !p.Addr.IsValid() {
		return errors.New("the far end offered no mesh address")
	}
	if !pair.InMesh(p.Addr) {
		return fmt.Errorf("%s is outside the mesh range", p.Addr)
	}

	n.mu.Lock()

	if p.NodeKey == n.file.NodeKey.Public() {
		n.mu.Unlock()
		return errors.New("that is this machine's own key")
	}

	// An address collision is remote — 22 bits of derived host space — but it
	// has to be caught rather than producing a mesh where two peers silently
	// answer to the same address and cryptokey routing sends packets to
	// whichever WireGuard matched first.
	self, _ := n.file.Self.Addr()
	if self == p.Addr {
		n.mu.Unlock()
		return fmt.Errorf("%s derives the same mesh address as this machine (%s); one of the two needs a new node key", displayName(p), p.Addr)
	}
	for _, existing := range n.file.Peers {
		if existing.Key == p.NodeKey {
			continue
		}
		if a, err := existing.Addr(); err == nil && a == p.Addr {
			n.mu.Unlock()
			return fmt.Errorf("%s derives the same mesh address as peer %s (%s); one of the two needs a new node key", displayName(p), existing.Name, p.Addr)
		}
	}

	node := netmap.Node{
		ID:        netmap.NodeID(len(n.file.Peers) + 2),
		Name:      displayName(p),
		Key:       p.NodeKey,
		DiscoKey:  p.DiscoKey,
		Addresses: []netip.Prefix{netip.PrefixFrom(p.Addr, p.Addr.BitLen())},
		Endpoints: p.Endpoints,
		RelayURL:  n.file.HomeRelay.URL,
	}

	replaced := false
	for i, existing := range n.file.Peers {
		if existing.Key == p.NodeKey {
			node.ID = existing.ID
			// A preshared key was agreed out of band and is not part of what a
			// knock carries, so re-pairing must not silently discard one.
			node.PresharedKey = existing.PresharedKey
			n.file.Peers[i] = node
			replaced = true
			break
		}
	}
	if !replaced {
		n.file.Peers = append(n.file.Peers, node)
	}

	saveErr := conf.Save(n.cfgPath, n.file)
	n.mu.Unlock()

	if saveErr != nil {
		return fmt.Errorf("record the new peer: %w", saveErr)
	}

	if err := n.applyLocal(); err != nil {
		return err
	}

	verb := "paired with"
	if replaced {
		verb = "re-paired with"
	}
	log.Printf("%s %s at %s", verb, node.Name, p.Addr)
	return nil
}

// displayName is what to call a machine that did not name itself.
func displayName(p magicsock.PairedPeer) string {
	if p.Name != "" {
		return p.Name
	}
	return "peer-" + shortKey(p.NodeKey.String())
}

func shortKey(s string) string {
	if len(s) > 6 {
		return s[:6]
	}
	return s
}

// applyLocal pushes the configuration's own netmap onto the running device.
//
// The serverless counterpart to apply: same work, different source. A managed
// node is reconfigured by a netmap arriving from a server; a serverless one by
// its own file changing underneath it, which happens exactly when a pairing
// completes.
func (n *node) applyLocal() error {
	m := n.netMap()

	if err := n.engine.SetConfig(m.WireGuardConfig()); err != nil {
		return fmt.Errorf("reconfigure the tunnel: %w", err)
	}
	if n.sock != nil {
		n.applyNetwork(m)
	}
	if err := n.router.Sync(m.Routes()); err != nil {
		log.Printf("warning: %v", err)
	}

	// Rebind published ports: a first peer is the moment a serverless node's
	// services become reachable by anyone.
	n.applyServices()
	return nil
}
