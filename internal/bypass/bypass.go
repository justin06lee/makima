// Package bypass keeps the tunnel's own traffic out of the tunnel.
//
// Using an exit node points the machine's default route into the tunnel.
// Everything the tunnel itself sends — WireGuard's UDP, the relay's TCP
// connection, the long poll to the control plane — would follow it, and a
// tunnel whose packets are routed into itself carries nothing. Worse than
// nothing when the exit node is reached through the relay: the relay's
// connection is sent through the tunnel, which is sent through the relay.
//
// Pinning a host route to the exit node over the old gateway, which is what
// makima used to do, covers exactly one of those destinations, and only one
// of the exit node's several addresses. The relay and the control plane —
// which on a home network are often the exit node's public address, not the
// one pinned — went into the tunnel regardless.
//
// So instead the sockets carrying the tunnel are bound to the physical
// interface while an exit node is in use: IP_BOUND_IF on macOS,
// SO_BINDTODEVICE on Linux. A bound socket leaves through its interface
// whatever the routing table says, which is the same thing Tailscale does and
// needs no knowledge of where the tunnel's packets are going.
package bypass

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// Interface is a network interface the tunnel's traffic is sent out of.
type Interface struct {
	Name  string
	Index int
}

func (i Interface) String() string { return i.Name }

// ErrUnsupported is a platform with no way to bind a socket to an interface.
var ErrUnsupported = errors.New("binding a socket to an interface is not supported on this platform")

// Binder binds the tunnel's sockets to one interface, or to none.
//
// The zero value and a nil *Binder are both valid and bind nothing, so code
// that never uses an exit node — the rootless node, the command line — can
// hold one without caring.
type Binder struct {
	mu    sync.Mutex
	iface *Interface

	// socks are the long-lived sockets opened before a binding changed, which
	// have to be rebound in place: the WireGuard socket, above all, whose
	// port every peer holds and which cannot simply be reopened.
	socks map[syscall.Conn]struct{}
}

// Bind binds every tracked socket, and every one opened from now on, to ifc.
func (b *Binder) Bind(ifc Interface) error {
	if b == nil {
		return ErrUnsupported
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.iface = &ifc
	return b.applyLocked()
}

// Unbind lets every tracked socket, and every later one, follow the routing
// table again.
func (b *Binder) Unbind() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.iface == nil {
		return nil
	}
	b.iface = nil
	return b.applyLocked()
}

// Bound is the interface sockets are bound to, if any.
func (b *Binder) Bound() (Interface, bool) {
	if b == nil {
		return Interface{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.iface == nil {
		return Interface{}, false
	}
	return *b.iface, true
}

func (b *Binder) applyLocked() error {
	var errs []error
	for s := range b.socks {
		rc, err := s.SyscallConn()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := bindSocket(rc, b.iface); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Track binds a long-lived socket now, and rebinds it whenever the binding
// changes, until the returned function is called.
func (b *Binder) Track(s syscall.Conn) (untrack func()) {
	if b == nil {
		return func() {}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socks == nil {
		b.socks = make(map[syscall.Conn]struct{})
	}
	b.socks[s] = struct{}{}
	if b.iface != nil {
		if rc, err := s.SyscallConn(); err == nil {
			_ = bindSocket(rc, b.iface)
		}
	}
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.socks, s)
	}
}

// Control binds a socket as it is created, for net.Dialer and
// net.ListenConfig. A no-op while nothing is bound.
func (b *Binder) Control(network, address string, c syscall.RawConn) error {
	ifc, ok := b.Bound()
	if !ok {
		return nil
	}
	return bindSocket(c, &ifc)
}

// DialContext dials the way the tunnel's own connections must: through the
// bound interface while there is one, name lookups included — a lookup sent
// into a tunnel that is not up yet is a control plane that can never be
// found by name.
func (b *Binder) DialContext(ctx context.Context, d *net.Dialer, network, address string) (net.Conn, error) {
	dd := *d
	if _, ok := b.Bound(); ok {
		dd.Control = b.Control
		dd.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				rd := net.Dialer{Timeout: 5 * time.Second, Control: b.Control}
				return rd.DialContext(ctx, network, address)
			},
		}
	}
	conn, err := dd.DialContext(ctx, network, address)
	if err != nil {
		if ifc, ok := b.Bound(); ok {
			return nil, fmt.Errorf("%w (dialled through %s, to stay out of the exit node's tunnel)", err, ifc)
		}
		return nil, err
	}
	return conn, nil
}
