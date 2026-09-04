package localports

import (
	"net"
	"net/netip"
	"testing"
)

func lo(port uint16) Listener {
	return Listener{Addr: netip.MustParseAddr("127.0.0.1"), Port: port}
}

func lo6(port uint16) Listener {
	return Listener{Addr: netip.MustParseAddr("::1"), Port: port}
}

func any4(port uint16) Listener {
	return Listener{Addr: netip.MustParseAddr("0.0.0.0"), Port: port}
}

func ports(ls []Listener) []uint16 {
	out := make([]uint16, len(ls))
	for i, l := range ls {
		out[i] = l.Port
	}
	return out
}

func equal(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestForwardable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		given   []Listener
		exclude map[uint16]bool
		want    []uint16
	}{
		{
			name:  "a loopback-only port is worth forwarding",
			given: []Listener{lo(11434)},
			want:  []uint16{11434},
		},
		{
			// The whole distinction this package exists to make: a wildcard
			// listener already answers on the mesh address.
			name:  "a wildcard port is already reachable",
			given: []Listener{any4(22)},
			want:  nil,
		},
		{
			// sshd on 0.0.0.0 plus something on 127.0.0.1:22 would still be
			// reachable via the wildcard, and binding would collide.
			name:  "a port with both bindings is left alone",
			given: []Listener{lo(8080), any4(8080)},
			want:  nil,
		},
		{
			name:  "the v4 and v6 halves of one service are one service",
			given: []Listener{lo(3000), lo6(3000)},
			want:  []uint16{3000},
		},
		{
			name:  "a deliberate bind to one real address is not second-guessed",
			given: []Listener{{Addr: netip.MustParseAddr("192.168.1.5"), Port: 9000}},
			want:  nil,
		},
		{
			name:    "excluded ports are dropped",
			given:   []Listener{lo(8088), lo(11434)},
			exclude: map[uint16]bool{8088: true},
			want:    []uint16{11434},
		},
		{
			name:  "the result is ordered by port",
			given: []Listener{lo(9000), lo(80), lo(443)},
			want:  []uint16{80, 443, 9000},
		},
		{
			name:  "nothing listening, nothing forwarded",
			given: nil,
			want:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ports(Forwardable(tc.given, tc.exclude))
			if !equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// A name learned from one address family must not be erased by the other.
func TestForwardableKeepsProcessName(t *testing.T) {
	v4 := lo(3000)
	v4.Process = "node"
	v6 := lo6(3000)

	for _, order := range [][]Listener{{v4, v6}, {v6, v4}} {
		got := Forwardable(order, nil)
		if len(got) != 1 {
			t.Fatalf("got %d listeners, want 1", len(got))
		}
		if got[0].Process != "node" {
			t.Fatalf("process name lost: %+v", got[0])
		}
	}
}

func TestName(t *testing.T) {
	if got := lo(11434).Name(); got != "ollama" {
		t.Fatalf("port 11434 named %q, want ollama", got)
	}

	// A well-known port wins over the process name, because "ollama" is more
	// use in a peer's status output than "ollama-runner" or "python3".
	l := lo(8888)
	l.Process = "python3"
	if got := l.Name(); got != "jupyter" {
		t.Fatalf("port 8888 named %q, want jupyter", got)
	}

	l = lo(45231)
	l.Process = "my-daemon"
	if got := l.Name(); got != "my-daemon" {
		t.Fatalf("unknown port named %q, want the process name", got)
	}

	if got := lo(45231).Name(); got != "" {
		t.Fatalf("a nameless listener named %q, want empty", got)
	}
}

// The platform code has to find a socket this test is definitely holding.
func TestListeningFindsARealSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	all, err := Listening()
	if err != nil {
		t.Skipf("enumeration unavailable here: %v", err)
	}

	for _, l := range all {
		if l.Port == port && l.LoopbackOnly() {
			return
		}
	}
	t.Fatalf("listening on 127.0.0.1:%d, but the scan of %d sockets missed it", port, len(all))
}

// And it has to classify a wildcard bind as already-reachable, or the daemon
// would try to republish every service that is fine as it is.
func TestListeningClassifiesWildcard(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	all, err := Listening()
	if err != nil {
		t.Skipf("enumeration unavailable here: %v", err)
	}

	if got := ports(Forwardable(all, nil)); contains(got, port) {
		t.Fatalf("port %d binds 0.0.0.0 but was selected for forwarding", port)
	}
}

func contains(xs []uint16, x uint16) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
