package main

import (
	"context"
	"log"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/hostaddr"
)

// netCheckInterval is how often the daemon looks at its own addresses.
//
// Listing the interfaces is cheap, and this is the whole of how quickly a
// laptop that has changed networks stops waiting on the old one.
const netCheckInterval = 3 * time.Second

// blipWindow is how long this machine may be without any network at all and
// still count as on the one it left when that comes back.
//
// Longer than a Wi-Fi drop or a roam between access points — the Jetson's
// took up to a minute — and shorter than anybody carries a laptop from one
// network to another that merely looks the same: every AT&T home hands out
// 192.168.1.x behind 192.168.1.254.
const blipWindow = 2 * time.Minute

// watchNetwork notices this machine moving to another network and acts at
// once rather than waiting for timeouts to find out.
//
// A laptop carried out of the house has a long poll open to a LAN address
// that no longer exists, a direct path to every peer through the same LAN, and
// a relay connection from an address it no longer holds. Each of those would
// eventually time out — the poll after a minute and a half, the paths after
// most of one, the relay whenever TCP gives up — and until they did, nothing
// worked. Noticing the move directly turns that into a few seconds.
//
// Not every change is a move, and treating one as such costs a reconnection
// from scratch: on a machine whose Wi-Fi drops and comes back, that was
// every peer's path, every public address learned, and the relay over tor,
// several times an hour. So a link that comes back to the network it left
// keeps all of it, and a new address on the same network keeps the paths.
func (n *node) watchNetwork(ctx context.Context) {
	tr := newNetTracker(networkState())
	t := time.NewTicker(netCheckInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := networkState()
		switch tr.observe(now, time.Now()) {
		case netAway:
			log.Print("network: no usable address; waiting for one")
		case netDown:
			log.Printf("network: down to %s; waiting to see whether the rest comes back", now)
		case netBack:
			log.Printf("network: back on %s; keeping the paths it had", now)
			n.networkBack()
		case netGrew:
			log.Printf("network: now on %s, more of the same network", now)
			n.networkGrew(ctx)
		case netRenumbered:
			log.Printf("network: now on %s, a new address on the same network", now)
			n.networkRenumbered(ctx)
		case netMoved:
			log.Printf("network changed: now on %s", now)
			n.networkChanged(ctx)
		}
	}
}

// networkChanged drops everything learned on the old network.
func (n *node) networkChanged(ctx context.Context) {
	// Before the relay is redialled below, so it is redialled out of the
	// interface the machine is on now.
	n.rebindExit()
	// The old router's mapping is the old network's public address. It goes
	// before the poll below is kicked, which would otherwise carry it to the
	// control plane again — the refresh that asks the new router for one runs
	// alongside, and has not answered by then.
	if n.pm != nil {
		n.pm.Forget()
	}
	if n.sock != nil {
		n.sock.NetworkChanged()
		go n.refreshEndpoints(ctx)
	}
	// The address the control plane answered at on the old network — its
	// onion address, away from home — may not be the best one on this; the
	// one the node joined through is tried first again.
	if n.client != nil {
		n.client.Rehome()
	}
	// The poll open now went out over the old network; start another, which
	// also carries the new endpoints to the control plane straight away.
	n.kickPoll()
}

// networkBack is the link coming back to the network it left, with the
// addresses it had: the paths, the router's mapping, the relay and the poll
// all still stand. The peers are asked at once whether the paths do.
func (n *node) networkBack() {
	n.rebindExit()
	if n.sock != nil {
		n.sock.LinkBack()
	}
}

// networkGrew is a new address on the network this machine is on, with
// none lost — the phone hotspot's IPv6 arriving a second after its IPv4.
// Nothing learned is stale; the new address is told to the control plane.
func (n *node) networkGrew(ctx context.Context) {
	n.rebindExit()
	if n.sock != nil {
		n.sock.LinkBack()
		go n.refreshEndpoints(ctx)
	}
	n.kickPoll()
}

// networkRenumbered is the same network, without an address this machine
// had: the router's mapping and the relay connection were the old
// address's, the paths are kept but proven again, and the control plane is
// the same one it was.
func (n *node) networkRenumbered(ctx context.Context) {
	n.rebindExit()
	if n.pm != nil {
		n.pm.Forget()
	}
	if n.sock != nil {
		n.sock.Renumbered()
		go n.refreshEndpoints(ctx)
	}
	n.kickPoll()
}

// netMove is what one look at the interfaces found.
type netMove int

const (
	netSame       netMove = iota // nothing to do
	netAway                      // no network at all
	netDown                      // less of the network than before, nothing new
	netBack                      // back to just what it had
	netGrew                      // the same network, with more addresses
	netRenumbered                // the same network, without an address it had
	netMoved                     // another network
)

func (m netMove) String() string {
	return [...]string{"same", "away", "down", "back", "grew", "renumbered", "moved"}[m]
}

// netState is where this machine is, as the interfaces say: its addresses —
// IPv4 ones, and IPv6 /64s, since a privacy address is rotated daily on the
// same network — and the networks they are on, IPv4 subnets and IPv6 /64s.
type netState struct {
	addrs []string
	nets  []netip.Prefix
}

// networkState is this machine's netState now.
func networkState() netState { return stateOf(hostaddr.NetworkPrefixes()) }

func stateOf(pfxs []netip.Prefix) netState {
	var s netState
	for _, p := range pfxs {
		a := p.Addr()
		if a.Is6() {
			p64, err := a.Prefix(64)
			if err != nil {
				continue
			}
			s.addrs = append(s.addrs, p64.String())
			s.nets = append(s.nets, p64)
			continue
		}
		s.addrs = append(s.addrs, a.String())
		s.nets = append(s.nets, p.Masked())
	}
	slices.Sort(s.addrs)
	s.addrs = slices.Compact(s.addrs)
	slices.SortFunc(s.nets, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	s.nets = slices.Compact(s.nets)
	return s
}

func (s netState) String() string { return strings.Join(s.addrs, " ") }
func (s netState) empty() bool    { return len(s.addrs) == 0 }
func (s netState) equal(o netState) bool {
	return slices.Equal(s.addrs, o.addrs) && slices.Equal(s.nets, o.nets)
}

// netTracker decides what each look at the interfaces means, against the
// network the daemon last acted on.
type netTracker struct {
	settled netState  // the network last acted on
	last    netState  // what the previous look saw
	downAt  time.Time // when it began to have less than settled; zero while it has it all
	awayAt  time.Time // when it last had no network at all; zero while it has one
}

func newNetTracker(now netState) *netTracker {
	return &netTracker{settled: now, last: now}
}

func (t *netTracker) observe(now netState, at time.Time) netMove {
	if now.equal(t.last) {
		// Part of the network gone for longer than any drop is not coming
		// back: settle on what is left.
		if !t.downAt.IsZero() && !now.empty() && at.Sub(t.downAt) > blipWindow {
			t.settle(now)
			return netRenumbered
		}
		return netSame
	}
	t.last = now

	if now.empty() {
		if t.downAt.IsZero() {
			t.downAt = at
		}
		t.awayAt = at
		return netAway
	}
	wasAway := !t.awayAt.IsZero()
	awayFor := at.Sub(t.awayAt)
	t.awayAt = time.Time{}

	lost := !subset(t.settled.addrs, now.addrs)
	gained := !subset(now.addrs, t.settled.addrs)
	switch {
	case wasAway && awayFor > blipWindow:
		t.settle(now)
		return netMoved
	case !gained && !lost:
		t.settle(now)
		return netBack
	case !gained:
		if t.downAt.IsZero() {
			t.downAt = at
		}
		return netDown
	case !overlap(t.settled.nets, now.nets):
		t.settle(now)
		return netMoved
	case !lost:
		t.settle(now)
		return netGrew
	default:
		t.settle(now)
		return netRenumbered
	}
}

func (t *netTracker) settle(now netState) {
	t.settled = now
	t.downAt = time.Time{}
}

// subset reports whether every element of a is in b.
func subset[T comparable](a, b []T) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

func overlap(a, b []netip.Prefix) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// fingerprint names the networks a set of addresses is on, the way netState
// prints them.
func fingerprint(addrs []netip.Addr) string {
	pfxs := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		pfxs = append(pfxs, netip.PrefixFrom(a, a.BitLen()))
	}
	return stateOf(pfxs).String()
}
