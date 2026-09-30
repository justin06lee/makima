// Package localports reports which TCP ports this machine is listening on,
// and on which addresses.
//
// It exists to answer one question the daemon asks every few seconds: what is
// running here that a peer would want and cannot currently reach?
//
// A service bound to 0.0.0.0 is already reachable at the node's mesh address
// — the mesh address is on this machine, so a wildcard listener is answering
// on it too, and forwarding would be both redundant and impossible (the bind
// would collide). A service bound only to 127.0.0.1 is the interesting case:
// it is deliberately refusing everything except this machine, and the tunnel
// cannot reach it either. Those are the ports worth forwarding, and telling
// the two apart is the whole job of this package.
package localports

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
)

// Listener is one listening TCP socket.
type Listener struct {
	// Addr is the address it is bound to.
	Addr netip.Addr

	// Port is the port it is bound to.
	Port uint16

	// Process is the program holding it, where the platform will say. Best
	// effort, and empty is normal: it is used to name a service in the UI, not
	// to decide anything.
	Process string
}

// LoopbackOnly reports whether this listener answers only its own machine.
func (l Listener) LoopbackOnly() bool { return l.Addr.IsLoopback() }

// Localhost reports whether it is bound to 127.0.0.1 or ::1 — localhost
// itself, rather than one of the other addresses in 127/8.
func (l Listener) Localhost() bool {
	return l.Addr == netip.AddrFrom4([4]byte{127, 0, 0, 1}) || l.Addr == netip.IPv6Loopback()
}

// Target is where a forward reaches it: the address it is bound to. A service
// listening only on ::1 refuses 127.0.0.1.
func (l Listener) Target() string {
	return net.JoinHostPort(l.Addr.String(), strconv.Itoa(int(l.Port)))
}

// Wildcard reports whether this listener answers on every address, which
// includes the mesh address.
func (l Listener) Wildcard() bool { return l.Addr.IsUnspecified() }

// Listening returns every listening TCP socket on this machine.
//
// Implemented per platform. An error means the enumeration failed, not that
// nothing is listening — callers should treat it as "no information" and leave
// whatever they already published alone, because concluding "nothing is
// running" from a failed read would tear down every automatic service on the
// machine.
func Listening() ([]Listener, error) { return listening() }

// Forwardable reduces a set of listeners to the ports worth publishing on the
// mesh automatically.
//
// The rules, in order:
//
//   - A port with a wildcard listener is dropped. It already answers on the
//     mesh address, so there is nothing to forward and a bind would collide.
//   - A port bound only to localhost — 127.0.0.1 or ::1 — is kept, and where
//     it is on both, it is forwarded to 127.0.0.1.
//   - Anything bound to one specific other address is dropped. It is
//     reachable at that address by whoever the operator meant, and second-
//     guessing a deliberate bind is not this package's business. That goes
//     for the rest of 127/8 too: systemd-resolved's stub resolver on
//     127.0.0.53, on every stock Ubuntu, is a bind nobody meant for the mesh,
//     and one a forward to localhost would never reach.
//   - Ports in exclude are dropped, which is how the daemon keeps its own
//     listeners from being republished back onto the mesh.
//
// The result is sorted by port so that a caller comparing it against what it
// published last time sees a stable order rather than map iteration noise.
func Forwardable(ls []Listener, exclude map[uint16]bool) []Listener {
	wildcard := make(map[uint16]bool, len(ls))
	for _, l := range ls {
		if l.Wildcard() {
			wildcard[l.Port] = true
		}
	}

	// One entry per port: the same service listening on both 127.0.0.1 and ::1
	// is one thing to publish, not two.
	seen := make(map[uint16]Listener, len(ls))
	for _, l := range ls {
		if !l.Localhost() || wildcard[l.Port] || exclude[l.Port] {
			continue
		}
		prev, ok := seen[l.Port]
		if !ok {
			seen[l.Port] = l
			continue
		}
		// The IPv4 address, so a service on both is forwarded where it
		// always was; and whichever record carries a process name, so the
		// IPv6 twin of a socket does not erase the name learned from the
		// IPv4 one.
		if l.Addr.Is4() {
			prev.Addr = l.Addr
		}
		if prev.Process == "" {
			prev.Process = l.Process
		}
		seen[l.Port] = prev
	}

	out := make([]Listener, 0, len(seen))
	for _, l := range seen {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// wellKnown gives a friendlier name than a process name would for the handful
// of services this is most often pointed at.
//
// Deliberately short. It is a courtesy for the common case, not a registry to
// be completed — an unrecognised port falls back to the process name, and
// then to nothing, and both are fine.
var wellKnown = map[uint16]string{
	11434: "ollama",
	8188:  "comfyui",
	8888:  "jupyter",
	3000:  "dev",
	5173:  "vite",
	7860:  "gradio",
	8000:  "http",
	8080:  "webui",
	5432:  "postgres",
	6379:  "redis",
	9090:  "prometheus",
	3306:  "mysql",
	27017: "mongo",
	1234:  "lmstudio",
	5000:  "flask",
}

// Name suggests a label for a listener, or "" when it has nothing to offer.
func (l Listener) Name() string {
	if n, ok := wellKnown[l.Port]; ok {
		return n
	}
	return l.Process
}
