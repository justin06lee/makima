package netcfg

import (
	"fmt"
	"net/netip"
	"sync"
)

// An exit node has two halves, and they run on different machines.
//
// On the node *offering* to be one, the kernel has to be willing to forward
// packets between the tunnel and the real network, and to masquerade them so
// replies come back — otherwise the upstream router receives a packet from
// 100.64.0.5 and has no idea where to send the answer. That is Advertiser.
//
// On the node *using* one, the default route has to point into the tunnel.
// That is the dangerous half: get it wrong and the machine loses the internet,
// including the route to the exit node itself, which is a bootstrap problem
// with no way out except a reboot. Client handles it by pinning a host route
// to the exit node over the original gateway *before* redirecting everything
// else, so the tunnel's own packets always have a way out.

// Advertiser makes this machine willing to route for others.
type Advertiser struct {
	iface string

	mu      sync.Mutex
	enabled bool
}

// NewAdvertiser builds one for the tunnel interface.
func NewAdvertiser(iface string) *Advertiser { return &Advertiser{iface: iface} }

// Enable turns on forwarding and masquerading.
func (a *Advertiser) Enable() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.enabled {
		return nil
	}
	if err := enableForwarding(a.iface); err != nil {
		return err
	}
	a.enabled = true
	return nil
}

// Disable reverses it.
func (a *Advertiser) Disable() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled {
		return nil
	}
	err := disableForwarding(a.iface)
	a.enabled = false
	return err
}

// Enabled reports whether forwarding is currently on.
func (a *Advertiser) Enabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enabled
}

// ExitClient redirects this machine's traffic through a peer.
type ExitClient struct {
	iface string

	mu       sync.Mutex
	active   bool
	exitAddr netip.Addr

	// pinned is the host route keeping the exit node itself reachable over the
	// original gateway. Without it, redirecting the default route would send
	// the tunnel's own packets into the tunnel.
	pinned  netip.Prefix
	gateway netip.Addr
}

// NewExitClient builds one for the tunnel interface.
func NewExitClient(iface string) *ExitClient { return &ExitClient{iface: iface} }

// Use routes all traffic through the exit node at exitAddr.
//
// endpoints are the exit node's real-world addresses — the ones outside the
// tunnel — which is what has to stay routed over the physical gateway. Passing
// none is refused rather than attempted: without a pinned route the redirect
// would cut off the very path it depends on.
func (c *ExitClient) Use(exitAddr netip.Addr, endpoints []netip.AddrPort, gateway netip.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.active && c.exitAddr == exitAddr {
		return nil
	}
	if len(endpoints) == 0 {
		return fmt.Errorf("refusing to route through %s: its real address is unknown, and redirecting the default route without pinning one would cut off the tunnel itself", exitAddr)
	}
	if !gateway.IsValid() {
		return fmt.Errorf("refusing to route through %s: no default gateway was found to pin its route over", exitAddr)
	}

	// Pin first, redirect second. The reverse order has a window in which the
	// machine has no working route to the exit node.
	pinned := netip.PrefixFrom(endpoints[0].Addr(), endpoints[0].Addr().BitLen())
	if err := addRouteVia(pinned, gateway); err != nil {
		return fmt.Errorf("pin route to exit node: %w", err)
	}

	if err := addDefaultViaInterface(c.iface); err != nil {
		_ = delRouteVia(pinned, gateway)
		return fmt.Errorf("redirect default route: %w", err)
	}

	c.active = true
	c.exitAddr = exitAddr
	c.pinned = pinned
	c.gateway = gateway
	return nil
}

// Stop restores normal routing.
func (c *ExitClient) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.active {
		return nil
	}

	// Remove the redirect before the pin, mirroring Use. Removing the pin
	// first would briefly route the exit node's own address into the tunnel.
	err := delDefaultViaInterface(c.iface)
	if e := delRouteVia(c.pinned, c.gateway); e != nil && err == nil {
		err = e
	}

	c.active = false
	c.exitAddr = netip.Addr{}
	return err
}

// Active reports whether traffic is currently redirected, and where.
func (c *ExitClient) Active() (netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exitAddr, c.active
}

// defaultHalves are the two prefixes that together cover everything.
//
// 0.0.0.0/1 and 128.0.0.0/1 rather than 0.0.0.0/0, so the real default route
// survives underneath. Longest-prefix match then sends everything through the
// tunnel while leaving the original gateway intact and instantly restorable —
// removing two routes is a far safer undo than reconstructing a default route
// from memory.
var defaultHalves = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
}
