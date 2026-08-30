package serve

import (
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func quiet() *log.Logger { return log.New(io.Discard, "", 0) }

// echoServer stands in for a service bound to localhost.
func echoServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// loopback stands in for the node's mesh address: an address that exists on
// this machine and that a listener can bind.
const loopback = "127.0.0.1"

func TestPublishesAndForwards(t *testing.T) {
	target := echoServer(t)

	m := New(quiet())
	defer m.Close()

	// Port 0 is not allowed, so pick a real one by asking the OS for a free
	// one and giving it straight back.
	port := freePort(t)
	m.Apply(netip.MustParseAddr(loopback), []Service{{Port: port, Target: target}})

	addr := joinPort(loopback, port)
	c, err := dialWithRetry(addr)
	if err != nil {
		t.Fatalf("published port never accepted a connection: %v", err)
	}
	defer c.Close()

	want := "through the tunnel"
	if _, err := c.Write([]byte(want)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != want {
		t.Errorf("got %q back, want %q", buf, want)
	}
}

// The whole security property: the listener exists on the mesh address and
// nowhere else, so nothing on the LAN can reach it even though the service is
// now reachable from every machine on the mesh.
func TestListensOnlyOnTheGivenAddress(t *testing.T) {
	target := echoServer(t)
	port := freePort(t)

	m := New(quiet())
	defer m.Close()
	m.Apply(netip.MustParseAddr(loopback), []Service{{Port: port, Target: target}})

	if _, err := dialWithRetry(joinPort(loopback, port)); err != nil {
		t.Fatalf("not listening on the address it was given: %v", err)
	}

	// Every other address on this machine must refuse. Binding 0.0.0.0 would
	// publish the service to the LAN, which is the thing this exists to avoid.
	for _, other := range otherLocalAddrs(t) {
		c, err := net.DialTimeout("tcp", joinPort(other, port), 300*time.Millisecond)
		if err == nil {
			c.Close()
			t.Errorf("the service is reachable at %s, so it was bound too widely", other)
		}
	}
}

func TestWithdrawingStopsListening(t *testing.T) {
	target := echoServer(t)
	port := freePort(t)
	addr := joinPort(loopback, port)

	m := New(quiet())
	defer m.Close()

	m.Apply(netip.MustParseAddr(loopback), []Service{{Port: port, Target: target}})
	if _, err := dialWithRetry(addr); err != nil {
		t.Fatal(err)
	}

	m.Apply(netip.MustParseAddr(loopback), nil)

	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		c.Close()
		t.Error("the port is still accepting connections after being withdrawn")
	}
}

// A published port whose target is not running is the single most confusing
// failure here: it looks exactly like a broken network from the far end. The
// status has to tell the two apart.
func TestStatusReportsADeadTarget(t *testing.T) {
	port := freePort(t)
	dead := joinPort("127.0.0.1", freePort(t))

	m := New(quiet())
	defer m.Close()
	m.Apply(netip.MustParseAddr(loopback), []Service{{Port: port, Target: dead}})

	st := m.Status()
	if len(st) != 1 {
		t.Fatalf("%d statuses, want 1", len(st))
	}
	if !st[0].Listening {
		t.Error("the port is not listening even though nothing is wrong with it")
	}
	if st[0].TargetUp {
		t.Error("a target with nothing behind it was reported as up")
	}
}

func TestFailedConnectionsAreCounted(t *testing.T) {
	port := freePort(t)
	dead := joinPort("127.0.0.1", freePort(t))

	m := New(quiet())
	defer m.Close()
	m.Apply(netip.MustParseAddr(loopback), []Service{{Port: port, Target: dead}})

	addr := joinPort(loopback, port)
	c, err := dialWithRetry(addr)
	if err != nil {
		t.Fatal(err)
	}
	// The proxy accepts, fails to reach the target, and closes.
	io.Copy(io.Discard, c)
	c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status()[0].Failed > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("a connection that could not reach its target was not counted as failed")
}

// A changed mesh address must rebind, or every listener is on an address the
// interface no longer holds and nothing can reach any of them.
func TestAddressChangeRebinds(t *testing.T) {
	target := echoServer(t)
	port := freePort(t)

	m := New(quiet())
	defer m.Close()

	m.Apply(netip.MustParseAddr(loopback), []Service{{Port: port, Target: target}})
	if _, err := dialWithRetry(joinPort(loopback, port)); err != nil {
		t.Fatal(err)
	}

	// Rebinding to the same address through a different value exercises the
	// same path a real address change takes.
	m.Apply(netip.MustParseAddr("127.0.0.2"), []Service{{Port: port, Target: target}})

	st := m.Status()
	if len(st) != 1 {
		t.Fatalf("%d statuses, want 1", len(st))
	}
	// 127.0.0.2 is bindable on macOS and Linux; if it is not here, the
	// listener records why rather than pretending.
	if st[0].Listening && st[0].Address == joinPort(loopback, port) {
		t.Error("still bound to the old address after the mesh address changed")
	}
}

// Nothing is bound before an address exists, and that must not be an error:
// the daemon calls Apply before its first netmap has landed.
func TestNoAddressYetIsNotAnError(t *testing.T) {
	m := New(quiet())
	defer m.Close()

	m.Apply(netip.Addr{}, []Service{{Port: 9999, Target: "127.0.0.1:1"}})

	st := m.Status()
	if len(st) != 1 {
		t.Fatalf("%d statuses, want 1", len(st))
	}
	if st[0].Listening {
		t.Error("something is listening despite there being no address to listen on")
	}
}

func TestParseSpec(t *testing.T) {
	cases := []struct {
		in     string
		port   uint16
		target string
	}{
		{"11434", 11434, "127.0.0.1:11434"},
		{"80:11434", 80, "127.0.0.1:11434"},
		{"8080:192.168.1.9:80", 8080, "192.168.1.9:80"},
	}
	for _, c := range cases {
		got, err := ParseSpec(c.in)
		if err != nil {
			t.Errorf("ParseSpec(%q): %v", c.in, err)
			continue
		}
		if got.Port != c.port || got.Target != c.target {
			t.Errorf("ParseSpec(%q) = :%d -> %s, want :%d -> %s",
				c.in, got.Port, got.Target, c.port, c.target)
		}
	}

	for _, bad := range []string{"", "0", "notaport", "1:2:3:4", "70000"} {
		if _, err := ParseSpec(bad); err == nil {
			t.Errorf("ParseSpec(%q) was accepted", bad)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := (Service{Port: 80, Target: "127.0.0.1:8080"}).Validate(); err != nil {
		t.Errorf("a valid service was rejected: %v", err)
	}
	for _, bad := range []Service{
		{Port: 0, Target: "127.0.0.1:80"},
		{Port: 80},
		{Port: 80, Target: "nonsense"},
		{Port: 80, Target: ":80"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

func TestTargetReachable(t *testing.T) {
	if !TargetReachable(echoServer(t)) {
		t.Error("a live target was reported unreachable")
	}
	if TargetReachable(joinPort("127.0.0.1", freePort(t))) {
		t.Error("a dead target was reported reachable")
	}
}

// --- helpers --------------------------------------------------------------

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// joinPort builds an address the way net expects, so a v6 literal is bracketed
// rather than concatenated into something unparseable.
func joinPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// dialWithRetry allows for the listener starting asynchronously.
func dialWithRetry(addr string) (net.Conn, error) {
	var lastErr error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			return c, nil
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	return nil, lastErr
}

// otherLocalAddrs are addresses this machine holds that are not the one the
// manager was told to bind.
func otherLocalAddrs(t *testing.T) []string {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if ip.To4() == nil || ip.IsLoopback() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}
