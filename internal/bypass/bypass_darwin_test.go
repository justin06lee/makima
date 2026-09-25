package bypass

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func boundIndex(t *testing.T, c *net.UDPConn) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var idx int
	var gerr error
	rc.Control(func(fd uintptr) {
		idx, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return idx
}

// The WireGuard socket is opened long before anyone picks an exit node, and
// peers hold its port, so it has to be bound and unbound in place.
func TestTrackedSocketFollowsTheBinding(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip(err)
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var b Binder
	untrack := b.Track(c)
	defer untrack()

	if got := boundIndex(t, c); got != 0 {
		t.Fatalf("bound to %d before anything asked", got)
	}
	if err := b.Bind(Interface{Name: lo.Name, Index: lo.Index}); err != nil {
		t.Fatal(err)
	}
	if got := boundIndex(t, c); got != lo.Index {
		t.Errorf("bound to %d, want %s (%d)", got, lo.Name, lo.Index)
	}
	if err := b.Unbind(); err != nil {
		t.Fatal(err)
	}
	if got := boundIndex(t, c); got != 0 {
		t.Errorf("still bound to %d after Unbind", got)
	}
}

// A socket created while a binding is in force is born bound.
func TestNewSocketIsBornBound(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip(err)
	}
	var b Binder
	if err := b.Bind(Interface{Name: lo.Name, Index: lo.Index}); err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: b.Control}
	pc, err := lc.ListenPacket(t.Context(), "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if got := boundIndex(t, pc.(*net.UDPConn)); got != lo.Index {
		t.Errorf("born bound to %d, want %d", got, lo.Index)
	}
}

func TestNilBinderBindsNothing(t *testing.T) {
	var b *Binder
	if _, ok := b.Bound(); ok {
		t.Error("a nil binder says it is bound")
	}
	if err := b.Unbind(); err != nil {
		t.Error(err)
	}
	b.Track(nil)()
}

// The point of it all: a socket bound to an interface does not take the
// routing table's word for where a packet goes. Bound to loopback, an IPv4
// packet for the internet — sent from a dual-stack socket, as WireGuard's is
// — has nowhere to go, where an unbound one would leave by the default route.
func TestBoundDualStackSocketIgnoresTheDefaultRoute(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip(err)
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	far := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9}

	if _, err := c.WriteToUDP([]byte("x"), far); err != nil {
		t.Skipf("no default route here to compare against: %v", err)
	}
	var b Binder
	defer b.Track(c)()
	if err := b.Bind(Interface{Name: lo.Name, Index: lo.Index}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteToUDP([]byte("x"), far); err == nil {
		t.Error("a socket bound to loopback still sent an IPv4 packet out by the default route")
	}
}

// Loopback is not out of the tunnel's way or into it — it is this machine —
// and a socket bound to the Wi-Fi cannot reach it. With a local DNS stub
// (systemd-resolved's 127.0.0.53, or a DNS proxy on a Mac), binding every
// dial made every name lookup fail while an exit node was in use.
func TestLoopbackDialsAreNotBound(t *testing.T) {
	var phys *net.Interface
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagLoopback == 0 && ifc.Flags&net.FlagPointToPoint == 0 {
			if addrs, _ := ifc.Addrs(); len(addrs) > 0 {
				phys = &ifc
				break
			}
		}
	}
	if phys == nil {
		t.Skip("no physical interface here")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var b Binder
	if err := b.Bind(Interface{Name: phys.Name, Index: phys.Index}); err != nil {
		t.Fatal(err)
	}
	c, err := b.DialContext(t.Context(), &net.Dialer{}, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("a dial to loopback while bound to %s: %v", phys.Name, err)
	}
	c.Close()
}
