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

// watchNetwork notices this machine moving to another network and acts at
// once rather than waiting for timeouts to find out.
//
// A laptop carried out of the house has a long poll open to a LAN address
// that no longer exists, a direct path to every peer through the same LAN, and
// a relay connection from an address it no longer holds. Each of those would
// eventually time out — the poll after a minute and a half, the paths after
// most of one, the relay whenever TCP gives up — and until they did, nothing
// worked. Noticing the move directly turns that into a few seconds.
func (n *node) watchNetwork(ctx context.Context) {
	last := networkFingerprint()
	t := time.NewTicker(netCheckInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := networkFingerprint()
		if now == last {
			continue
		}
		last = now
		if now == "" {
			log.Print("network: no usable address; waiting for one")
			continue
		}
		log.Printf("network changed: now on %s", now)
		n.networkChanged(ctx)
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
	// The poll open now went out over the old network; start another, which
	// also carries the new endpoints to the control plane straight away.
	n.kickPoll()
}

// networkFingerprint names the networks this machine is on: its IPv4
// addresses, and the /64 prefixes of its IPv6 ones. Prefixes rather than
// addresses because an IPv6 privacy address is rotated every day on the same
// network, and that is not a move.
func networkFingerprint() string {
	return fingerprint(hostaddr.NetworkAddrs())
}

func fingerprint(addrs []netip.Addr) string {
	var parts []string
	for _, a := range addrs {
		if a.Is6() {
			p, err := a.Prefix(64)
			if err != nil {
				continue
			}
			parts = append(parts, p.String())
			continue
		}
		parts = append(parts, a.String())
	}
	slices.Sort(parts)
	return strings.Join(slices.Compact(parts), " ")
}
