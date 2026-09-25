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
// including its way to the exit node itself, which is a bootstrap problem
// with no way out except a reboot. So the tunnel's own traffic is given a way
// out *before* everything else is redirected: its sockets are bound to the
// physical interface, or on a static mesh, the exit node is pinned over the
// original gateway. See ExitClient.

// Advertiser makes this machine willing to route for others.
type Advertiser struct {
	iface string

	mu      sync.Mutex
	enabled bool
	mesh    netip.Prefix
}

// NewAdvertiser builds one for the tunnel interface.
func NewAdvertiser(iface string) *Advertiser { return &Advertiser{iface: iface} }

// Enable turns on forwarding and masquerading for the mesh self is on.
func (a *Advertiser) Enable(self netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.enabled {
		return nil
	}
	mesh := MeshRange
	if LegacyMeshRange.Contains(self) {
		mesh = LegacyMeshRange
	}
	if err := enableForwarding(a.iface, mesh); err != nil {
		return err
	}
	a.enabled = true
	a.mesh = mesh
	return nil
}

// Disable reverses it.
func (a *Advertiser) Disable() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled {
		return nil
	}
	err := disableForwarding(a.iface, a.mesh)
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
//
// Redirecting is only half of it. Once the default route points into the
// tunnel, the tunnel's own packets have to be kept out of it, or they are
// sent into themselves. On a node with makima's own socket that is done by
// binding the sockets to the physical interface (internal/bypass), which the
// caller does before Use and undoes after Stop. A hand-written static mesh has
// no such socket — WireGuard opens its own — so there the exit node's known
// addresses are pinned over the old gateway instead: Use's pins.
type ExitClient struct {
	iface string

	mu       sync.Mutex
	active   bool
	exitAddr netip.Addr

	// pinned are the host routes keeping a static mesh's exit node reachable
	// over the original gateway, and gateway that gateway.
	pinned  []netip.Prefix
	gateway netip.Addr
}

// NewExitClient builds one for the tunnel interface.
func NewExitClient(iface string) *ExitClient { return &ExitClient{iface: iface} }

// Use routes all traffic through the exit node at exitAddr.
//
// Moving from one exit node to another changes no route: the default route
// points into the tunnel either way, and which peer carries it is WireGuard's
// business, decided by which peer holds the default-route halves. Only the
// first Use installs anything.
//
// pins, with gateway, are addresses to keep routed over the original gateway
// — for a node whose tunnel sockets cannot be bound, the exit node's own. A
// node that binds its sockets passes none.
func (c *ExitClient) Use(exitAddr netip.Addr, pins []netip.Addr, gateway netip.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.active {
		c.exitAddr = exitAddr
		return nil
	}
	if len(pins) > 0 && !gateway.IsValid() {
		return fmt.Errorf("refusing to route through %s: no default gateway was found to keep it reachable over", exitAddr)
	}

	// Pin first, redirect second. The reverse order has a window in which the
	// machine has no working route to the exit node.
	var pinned []netip.Prefix
	undo := func() {
		for _, p := range pinned {
			_ = delRouteVia(p, gateway)
		}
	}
	for _, a := range pins {
		p := netip.PrefixFrom(a, a.BitLen())
		if err := addRouteVia(p, gateway); err != nil {
			undo()
			return fmt.Errorf("pin route to exit node: %w", err)
		}
		pinned = append(pinned, p)
	}

	if err := addDefaultViaInterface(c.iface); err != nil {
		_ = delDefaultViaInterface(c.iface)
		undo()
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

	// Remove the redirect before the pins, mirroring Use. Removing a pin
	// first would briefly route the exit node's own address into the tunnel.
	err := delDefaultViaInterface(c.iface)
	for _, p := range c.pinned {
		if e := delRouteVia(p, c.gateway); e != nil && err == nil {
			err = e
		}
	}

	c.active = false
	c.exitAddr = netip.Addr{}
	c.pinned = nil
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
