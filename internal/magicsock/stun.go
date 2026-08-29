package magicsock

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/justin06lee/makima/internal/stun"
)

// stunTimeout is how long a binding transaction stays open.
const stunTimeout = 3 * time.Second

// QuerySTUN asks public servers what address our packets appear to come from.
//
// The request goes out of the same socket WireGuard uses, which is the entire
// reason this lives here rather than in package stun. A NAT hands out one
// mapping per socket; a query from any other socket would report an address
// that no peer can reach, and would do so convincingly.
//
// Sending is all this does. The answer arrives on the normal receive path,
// where it is matched by transaction ID and folded into the observed-address
// set, because a shared socket has no way to read "the next packet" without
// stealing one from WireGuard.
func (c *Conn) QuerySTUN(ctx context.Context, servers []string) error {
	c.mu.RLock()
	pc := c.pconn
	c.mu.RUnlock()
	if pc == nil {
		return net.ErrClosed
	}

	var lastErr error
	sent := 0

	for _, s := range servers {
		addr, err := resolveUDP(ctx, s)
		if err != nil {
			lastErr = err
			continue
		}

		req, tx, err := stun.Request()
		if err != nil {
			return err
		}

		c.stunMu.Lock()
		c.expireSTUNLocked()
		c.stunTx[tx] = time.Now()
		c.stunMu.Unlock()

		if _, err := pc.WriteToUDPAddrPort(req, addr); err != nil {
			lastErr = err
			continue
		}
		sent++
	}

	if sent == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no servers configured")
		}
		return fmt.Errorf("stun: %w", lastErr)
	}
	return nil
}

// handleSTUN folds a binding response into the observed-address set.
func (c *Conn) handleSTUN(b []byte) {
	tx, ok := stun.ResponseTxID(b)
	if !ok {
		return
	}

	c.stunMu.Lock()
	_, known := c.stunTx[tx]
	if known {
		delete(c.stunTx, tx)
	}
	c.stunMu.Unlock()

	if !known {
		// An unmatched transaction is either a timed-out request or somebody
		// spraying forged responses at us. Twelve random bytes make the second
		// hopeless, which is exactly why the ID is checked before the address
		// inside is believed.
		return
	}

	addr, ok := stun.ParseResponse(b)
	if !ok {
		return
	}
	c.noteSelfObservation(normalise(addr))
}

func (c *Conn) expireSTUNLocked() {
	for tx, at := range c.stunTx {
		if time.Since(at) > stunTimeout {
			delete(c.stunTx, tx)
		}
	}
}

// NoteSelfObservation records an address something else reported seeing us at.
//
// Exported for the port mapper, which learns an external address from the
// router rather than from a packet, and so has no other way in.
func (c *Conn) NoteSelfObservation(addr netip.AddrPort) { c.noteSelfObservation(addr) }

// resolveUDP resolves a host:port with the context's deadline respected.
func resolveUDP(ctx context.Context, s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse %q: %w", s, err)
	}

	var r net.Resolver
	// IPv4 only: the observed address is advertised to peers, and peers only
	// probe IPv4 endpoints for now.
	addrs, err := r.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve %q: no addresses", host)
	}

	p, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse port %q: %w", port, err)
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(p)), nil
}
