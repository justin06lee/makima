// Package serve exposes a machine's local services on the mesh.
//
// This exists because of a problem that looks like a networking problem and is
// not one. A service on a home server is almost always listening on
// 127.0.0.1 — Ollama, ComfyUI, Open WebUI, Jupyter, vLLM all default to it —
// so another machine cannot reach it no matter how good the network between
// them is. The usual fix is to rebind the service to 0.0.0.0, which exposes it
// to every device on the LAN, and then to open a firewall port, and then to
// forward that port on the router, and then to discover that the router will
// not hairpin so it works from outside the house and not from inside it.
//
// Every step of that is a step in the wrong direction. The service was right
// to bind to localhost.
//
// So instead the daemon listens on the node's *mesh* address and forwards to
// the service's localhost port. Nothing about the service changes. Nothing on
// the LAN can reach the listener, because the mesh address only exists inside
// the tunnel. No firewall port is opened to the network, no port is forwarded,
// and the router is not involved at all — which is why hairpinning stops
// mattering: the packets never go near it.
//
// What reaches the service is exactly what got through WireGuard's
// cryptographic authentication and then the mesh's access policy. "Requests
// that arrive in the name of makima just work" is the goal, and this is the
// piece that makes it literal.
package serve

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// dialTimeout bounds connecting to the local service.
//
// Short, because the target is nearly always on this machine: a localhost
// connection either succeeds immediately or fails immediately, and anything in
// between means the service is wedged rather than slow.
const dialTimeout = 5 * time.Second

// Service is one local port published to the mesh.
type Service struct {
	// Name is a label, used by the UI and status output. Optional.
	Name string `json:"name,omitempty"`

	// Port is the port to listen on, on this node's mesh address.
	Port uint16 `json:"port"`

	// Target is where to forward to, "host:port". Almost always a localhost
	// address; allowed to be any host so one node can publish a device that
	// cannot run makima itself — a printer, a switch, a NAS appliance.
	Target string `json:"target"`
}

// String renders a service the way the CLI prints it.
func (s Service) String() string {
	if s.Name != "" {
		return fmt.Sprintf("%s (:%d -> %s)", s.Name, s.Port, s.Target)
	}
	return fmt.Sprintf(":%d -> %s", s.Port, s.Target)
}

// Validate reports whether a service is usable.
func (s Service) Validate() error {
	if s.Port == 0 {
		return errors.New("serve: port 0 is not a port")
	}
	if s.Target == "" {
		return errors.New("serve: no target")
	}
	host, port, err := net.SplitHostPort(s.Target)
	if err != nil {
		return fmt.Errorf("serve: target %q is not host:port: %w", s.Target, err)
	}
	if host == "" {
		return fmt.Errorf("serve: target %q has no host", s.Target)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("serve: target %q has no valid port", s.Target)
	}
	return nil
}

// LocalTarget builds a target on this machine.
func LocalTarget(port uint16) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
}

// Status is what the CLI and UI report about a running service.
type Status struct {
	Service
	Listening bool   `json:"listening"`
	Address   string `json:"address,omitempty"`
	Error     string `json:"error,omitempty"`

	// Active is how many connections are open right now, Total how many there
	// have ever been, and Failed how many could not reach the target.
	//
	// Failed is the number worth looking at: a service that is published but
	// whose target is not running produces a connection refused on every
	// attempt, and that is by far the most common way this is misconfigured.
	Active uint64 `json:"active"`
	Total  uint64 `json:"total"`
	Failed uint64 `json:"failed"`

	// TargetUp is a live check of whether anything is listening on the target.
	TargetUp bool `json:"target_up"`
}

// Manager owns the listeners for one node.
type Manager struct {
	log *log.Logger

	mu      sync.Mutex
	addr    netip.Addr
	desired []Service
	running map[uint16]*listener
	closed  bool
}

// New builds a manager. Nothing listens until Apply.
func New(logger *log.Logger) *Manager {
	if logger == nil {
		logger = log.Default()
	}
	return &Manager{log: logger, running: make(map[uint16]*listener)}
}

// Apply makes the running listeners match svcs, on the given mesh address.
//
// Called on every netmap update, because the mesh address is not known until
// the control plane has assigned one and can in principle change. A changed
// address rebinds everything: a listener on an address the interface no longer
// holds is a listener nothing can reach, and it would fail silently.
func (m *Manager) Apply(addr netip.Addr, svcs []Service) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}

	rebindAll := addr != m.addr
	m.addr = addr
	m.desired = append([]Service(nil), svcs...)

	if rebindAll {
		for port, l := range m.running {
			l.close()
			delete(m.running, port)
		}
	}

	want := make(map[uint16]Service, len(svcs))
	for _, s := range svcs {
		want[s.Port] = s
	}

	// Stop what is no longer wanted, and anything whose target moved.
	for port, l := range m.running {
		s, ok := want[port]
		if ok && s.Target == l.svc.Target {
			continue
		}
		l.close()
		delete(m.running, port)
	}

	if !addr.IsValid() {
		// No mesh address yet. Not an error: the daemon calls this before its
		// first netmap has landed, and the next call will have one.
		return
	}

	for _, s := range svcs {
		if _, ok := m.running[s.Port]; ok {
			continue
		}
		l := m.start(addr, s)
		m.running[s.Port] = l
	}
}

// start begins listening for one service.
//
// A failure to bind is recorded rather than returned. One service whose port
// is already taken must not stop the others from coming up, and the reason is
// far more useful sitting in the status output where somebody will look for it
// than in a log line that scrolled past an hour ago.
func (m *Manager) start(addr netip.Addr, s Service) *listener {
	l := &listener{svc: s, log: m.log, done: make(chan struct{})}

	bind := net.JoinHostPort(addr.String(), strconv.Itoa(int(s.Port)))
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		l.err = err.Error()
		m.log.Printf("serve: cannot publish %s: %v", s, err)
		return l
	}

	l.ln = ln
	l.address = bind
	go l.accept()

	m.log.Printf("serve: %s on %s", s, bind)
	return l
}

// Status reports every configured service, running or not.
func (m *Manager) Status() []Status {
	m.mu.Lock()
	desired := append([]Service(nil), m.desired...)
	running := make(map[uint16]*listener, len(m.running))
	for p, l := range m.running {
		running[p] = l
	}
	m.mu.Unlock()

	out := make([]Status, 0, len(desired))
	for _, s := range desired {
		st := Status{Service: s, TargetUp: TargetReachable(s.Target)}
		if l, ok := running[s.Port]; ok {
			st.Listening = l.ln != nil
			st.Address = l.address
			st.Error = l.err
			st.Active = l.active.Load()
			st.Total = l.total.Load()
			st.Failed = l.failed.Load()
		}
		out = append(out, st)
	}
	return out
}

// Close stops everything.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	for port, l := range m.running {
		l.close()
		delete(m.running, port)
	}
}

// TargetReachable reports whether anything is listening on a target right now.
//
// The single most useful diagnostic this package can offer. A published
// service whose target is not running behaves exactly like a broken network
// from the other end — the connection is accepted by the tunnel and then dies
// — and this is what tells the two apart.
func TargetReachable(target string) bool {
	c, err := net.DialTimeout("tcp", target, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// listener is one published port.
type listener struct {
	svc     Service
	log     *log.Logger
	ln      net.Listener
	address string
	err     string

	active atomic.Uint64
	total  atomic.Uint64
	failed atomic.Uint64

	closeOnce sync.Once
	done      chan struct{}
}

func (l *listener) accept() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go l.proxy(conn)
	}
}

func (l *listener) proxy(from net.Conn) {
	defer from.Close()

	l.total.Add(1)
	l.active.Add(1)
	defer l.active.Add(^uint64(0)) // atomic decrement

	to, err := net.DialTimeout("tcp", l.svc.Target, dialTimeout)
	if err != nil {
		l.failed.Add(1)
		// Logged once per failure because this is the error people actually
		// need to see: the tunnel is fine and the service is not running.
		l.log.Printf("serve: %s: cannot reach %s: %v", l.svc, l.svc.Target, err)
		return
	}
	defer to.Close()

	if tc, ok := from.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if tc, ok := to.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	// Copy both ways and finish when either direction does. Half-closing the
	// far side on EOF matters for protocols that signal end-of-request that
	// way — HTTP/1.0 bodies, and anything piped over a raw socket — where
	// tearing the whole connection down instead loses the response.
	done := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(to, from)
		if tc, ok := to.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(from, to)
		if tc, ok := from.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}

func (l *listener) close() {
	l.closeOnce.Do(func() {
		close(l.done)
		if l.ln != nil {
			l.ln.Close()
		}
	})
}

// ParseSpec reads the forms the CLI accepts.
//
//	11434              publish localhost:11434 on mesh port 11434
//	80:11434           publish localhost:11434 on mesh port 80
//	80:192.168.1.9:80  publish another machine's port on mesh port 80
//
// The middle form is the one worth supporting carefully: wanting a service on
// a nicer port than it chose for itself is the common case, and making people
// write out "127.0.0.1" to say "here" is friction for no benefit.
func ParseSpec(spec string) (Service, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Service{}, errors.New("serve: nothing to publish")
	}

	parts := strings.Split(spec, ":")
	switch len(parts) {
	case 1:
		p, err := parsePort(parts[0])
		if err != nil {
			return Service{}, err
		}
		return Service{Port: p, Target: LocalTarget(p)}, nil

	case 2:
		meshPort, err := parsePort(parts[0])
		if err != nil {
			return Service{}, err
		}
		localPort, err := parsePort(parts[1])
		if err != nil {
			return Service{}, err
		}
		return Service{Port: meshPort, Target: LocalTarget(localPort)}, nil

	case 3:
		meshPort, err := parsePort(parts[0])
		if err != nil {
			return Service{}, err
		}
		s := Service{Port: meshPort, Target: net.JoinHostPort(parts[1], parts[2])}
		return s, s.Validate()

	default:
		return Service{}, fmt.Errorf("serve: cannot read %q; try PORT, MESHPORT:PORT, or MESHPORT:HOST:PORT", spec)
	}
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("serve: %q is not a port", s)
	}
	if n == 0 {
		return 0, errors.New("serve: port 0 is not a port")
	}
	return uint16(n), nil
}
