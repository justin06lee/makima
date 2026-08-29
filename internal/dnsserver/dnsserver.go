// Package dnsserver answers name lookups for the mesh.
//
// It resolves exactly one thing — a node's name under the mesh domain, in both
// directions — and refuses everything else. That narrowness is the design.
// A resolver that forwarded unknown names would become a general DNS proxy on
// every machine in the mesh, which is a much larger thing to get right and a
// much larger thing to get wrong: a misconfigured forwarder is an open
// resolver, and an open resolver is an amplification source.
//
// So mesh names resolve here and every other name is answered with REFUSED,
// which tells the operating system to ask its real resolver instead. Combined
// with split-DNS configuration — registering this server for the mesh domain
// only — a node's ordinary DNS is never touched, and a crashed daemon takes
// mesh names down with it rather than the whole internet.
package dnsserver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/justin06lee/makima/internal/netmap"
)

// Port is where the resolver listens on the node's mesh address.
const Port = 53

// ttl is how long an answer may be cached.
//
// Deliberately short. Mesh membership changes are pushed within milliseconds
// and a name whose address is cached for an hour would outlive several of
// them; five seconds keeps a resolver's cache honest without making every
// lookup a round trip.
const ttl = 5

// maxMessage is the largest DNS message accepted over UDP, per RFC 1035.
// Anything larger is a resolver expecting EDNS0, which this server does not
// advertise.
const maxMessage = 512

// Server answers mesh name lookups.
type Server struct {
	log *log.Logger

	mu      sync.RWMutex
	domain  string
	forward map[string]netip.Addr // "laptop." -> 100.64.0.1
	reverse map[netip.Addr]string // 100.64.0.1 -> "laptop"

	conn      *net.UDPConn
	closeOnce sync.Once
}

// New starts a resolver bound to addr.
//
// Bound to the node's own mesh address rather than a wildcard, so the resolver
// is reachable from this machine and from peers, and from nowhere else. A
// wildcard bind on a laptop is a DNS server on every coffee shop network it
// ever joins.
func New(addr netip.Addr, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.Default()
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: addr.AsSlice(), Port: Port})
	if err != nil {
		return nil, fmt.Errorf("dns: listen on %s:%d: %w", addr, Port, err)
	}

	s := &Server{
		log:     logger,
		conn:    conn,
		forward: make(map[string]netip.Addr),
		reverse: make(map[netip.Addr]string),
	}
	go s.serve()
	return s, nil
}

// Addr is where the resolver is listening.
func (s *Server) Addr() netip.AddrPort {
	if s.conn == nil {
		return netip.AddrPort{}
	}
	a := s.conn.LocalAddr().(*net.UDPAddr)
	addr, _ := netip.AddrFromSlice(a.IP)
	return netip.AddrPortFrom(addr.Unmap(), uint16(a.Port))
}

// SetRecords replaces the zone with the current netmap.
func (s *Server) SetRecords(domain string, self netmap.Node, peers []netmap.Node) {
	forward := make(map[string]netip.Addr, len(peers)+1)
	reverse := make(map[netip.Addr]string, len(peers)+1)

	add := func(n netmap.Node) {
		addr, err := n.Addr()
		if err != nil {
			return
		}
		name := normaliseName(n.Name)
		if name == "" {
			return
		}
		forward[name] = addr
		// First writer wins for reverse lookups. Two nodes cannot share an
		// address, so a collision here means a stale record, and the newer one
		// arrives later in the peer list.
		reverse[addr] = n.Name
	}

	add(self)
	for _, p := range peers {
		add(p)
	}

	s.mu.Lock()
	s.domain = strings.ToLower(strings.Trim(domain, "."))
	s.forward = forward
	s.reverse = reverse
	s.mu.Unlock()
}

// Close stops the resolver.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		if s.conn != nil {
			s.conn.Close()
		}
	})
}

func (s *Server) serve() {
	buf := make([]byte, maxMessage)

	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		resp, err := s.respond(buf[:n])
		if err != nil || resp == nil {
			continue
		}
		// Best effort. A resolver that does not get an answer retries or falls
		// through to its next server, which is the behaviour we want anyway.
		_, _ = s.conn.WriteToUDPAddrPort(resp, from)
	}
}

// respond builds an answer for one query.
func (s *Server) respond(q []byte) ([]byte, error) {
	msg, err := parseQuery(q)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	domain := s.domain
	forward := s.forward
	reverse := s.reverse
	s.mu.RUnlock()

	switch msg.qtype {
	case typeA:
		name, ok := stripDomain(msg.name, domain)
		if !ok {
			return refused(msg), nil
		}
		addr, ok := forward[name]
		if !ok {
			// The name is in our domain but not a node. NXDOMAIN rather than
			// REFUSED: this server is authoritative for the mesh domain, and
			// saying "no such name" is the true answer, where REFUSED would
			// send the resolver off to ask the public internet about a private
			// name.
			return nxdomain(msg), nil
		}
		return answerA(msg, addr), nil

	case typeAAAA:
		if _, ok := stripDomain(msg.name, domain); !ok {
			return refused(msg), nil
		}
		// Mesh addresses are IPv4 only for now. An empty NOERROR is the
		// correct way to say "this name exists, but not with that type" —
		// NXDOMAIN here would make a dual-stack resolver conclude the name
		// does not exist at all and never try the A record.
		return emptyAnswer(msg), nil

	case typePTR:
		addr, ok := arpaToAddr(msg.name)
		if !ok {
			return refused(msg), nil
		}
		name, ok := reverse[addr]
		if !ok {
			return nxdomain(msg), nil
		}
		return answerPTR(msg, name+"."+domain+"."), nil
	}

	return refused(msg), nil
}

// --- message handling ---------------------------------------------------

const (
	typeA    = 1
	typePTR  = 12
	typeAAAA = 28

	rcodeNoError  = 0
	rcodeNXDomain = 3
	rcodeRefused  = 5
)

type query struct {
	id       uint16
	rd       bool
	name     string // lowercase, trailing dot stripped
	qtype    uint16
	qclass   uint16
	rawQName []byte // the encoded question, echoed verbatim in the answer
}

// parseQuery reads the single question a DNS query carries.
//
// Only the first question is read, and only queries with exactly one are
// accepted. Multi-question queries are permitted by the wire format and
// supported by essentially nothing, and handling them would mean deciding what
// a partial answer means.
func parseQuery(b []byte) (*query, error) {
	if len(b) < 12 {
		return nil, errors.New("dns: message too short")
	}

	flags := binary.BigEndian.Uint16(b[2:4])
	if flags&0x8000 != 0 {
		return nil, errors.New("dns: not a query")
	}
	if binary.BigEndian.Uint16(b[4:6]) != 1 {
		return nil, errors.New("dns: expected exactly one question")
	}

	q := &query{
		id: binary.BigEndian.Uint16(b[0:2]),
		rd: flags&0x0100 != 0,
	}

	var labels []string
	i := 12
	start := i

	for {
		if i >= len(b) {
			return nil, errors.New("dns: truncated question")
		}
		n := int(b[i])
		if n == 0 {
			i++
			break
		}
		// Compression pointers cannot appear in a question — there is nothing
		// earlier in the message to point at — so a high-bits label here is
		// malformed rather than something to follow.
		if n&0xc0 != 0 {
			return nil, errors.New("dns: compression pointer in question")
		}
		i++
		if i+n > len(b) {
			return nil, errors.New("dns: truncated label")
		}
		labels = append(labels, strings.ToLower(string(b[i:i+n])))
		i += n
	}

	if i+4 > len(b) {
		return nil, errors.New("dns: truncated question type")
	}
	q.qtype = binary.BigEndian.Uint16(b[i : i+2])
	q.qclass = binary.BigEndian.Uint16(b[i+2 : i+4])
	q.rawQName = b[start : i+4]
	q.name = strings.Join(labels, ".")
	return q, nil
}

// header builds a response header with the given answer count and rcode.
func (q *query) header(answers int, rcode uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], q.id)

	// QR set, authoritative. RA is deliberately left clear: this server does
	// not recurse, and claiming otherwise invites a resolver to send it
	// everything.
	flags := uint16(0x8400) | rcode
	if q.rd {
		flags |= 0x0100 // echo RD, as required
	}
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], 1)
	binary.BigEndian.PutUint16(b[6:8], uint16(answers))
	return b
}

func refused(q *query) []byte {
	return append(q.header(0, rcodeRefused), q.rawQName...)
}

func nxdomain(q *query) []byte {
	return append(q.header(0, rcodeNXDomain), q.rawQName...)
}

func emptyAnswer(q *query) []byte {
	return append(q.header(0, rcodeNoError), q.rawQName...)
}

func answerA(q *query, addr netip.Addr) []byte {
	b := append(q.header(1, rcodeNoError), q.rawQName...)

	// 0xc00c is a compression pointer to offset 12, where the question's name
	// begins. Every resolver understands it and it saves repeating the name.
	b = append(b, 0xc0, 0x0c)
	b = binary.BigEndian.AppendUint16(b, typeA)
	b = binary.BigEndian.AppendUint16(b, q.qclass)
	b = binary.BigEndian.AppendUint32(b, ttl)

	v4 := addr.As4()
	b = binary.BigEndian.AppendUint16(b, 4)
	return append(b, v4[:]...)
}

func answerPTR(q *query, name string) []byte {
	b := append(q.header(1, rcodeNoError), q.rawQName...)

	b = append(b, 0xc0, 0x0c)
	b = binary.BigEndian.AppendUint16(b, typePTR)
	b = binary.BigEndian.AppendUint16(b, q.qclass)
	b = binary.BigEndian.AppendUint32(b, ttl)

	encoded := encodeName(name)
	b = binary.BigEndian.AppendUint16(b, uint16(len(encoded)))
	return append(b, encoded...)
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.Trim(name, "."), ".") {
		if label == "" || len(label) > 63 {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// stripDomain removes the mesh suffix, reporting whether the name was in it.
func stripDomain(name, domain string) (string, bool) {
	if domain == "" {
		return "", false
	}
	suffix := "." + domain
	if !strings.HasSuffix(name, suffix) {
		return "", false
	}
	return strings.TrimSuffix(name, suffix), true
}

// normaliseName renders a node name as a DNS label.
//
// Node names come from hostnames, which routinely contain characters DNS does
// not allow. Rewriting rather than rejecting means a machine called
// "Justin's MacBook Pro" still gets a working name instead of silently having
// none.
func normaliseName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-':
			b.WriteRune('-')
		case r == ' ' || r == '.' || r == '_':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// arpaToAddr decodes a reverse-lookup name back into an address.
func arpaToAddr(name string) (netip.Addr, bool) {
	const suffix = ".in-addr.arpa"
	if !strings.HasSuffix(name, suffix) {
		return netip.Addr{}, false
	}

	parts := strings.Split(strings.TrimSuffix(name, suffix), ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}

	// The labels are the octets in reverse, which is what makes the reverse
	// tree delegable in the same direction as the forward one.
	var b [4]byte
	for i, p := range parts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 0 || n > 255 {
			return netip.Addr{}, false
		}
		b[3-i] = byte(n)
	}
	return netip.AddrFrom4(b), true
}

// Ready reports whether the server has records to serve, so a caller can avoid
// pointing the OS at an empty resolver.
func (s *Server) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.domain != "" && len(s.forward) > 0
}

// Domain is the suffix currently served.
func (s *Server) Domain() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.domain
}
