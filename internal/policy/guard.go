package policy

import (
	"container/list"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Guard holds the filter a node is currently enforcing and applies it to
// packets.
//
// The filter is swapped wholesale on every netmap update, from the poll
// goroutine, while the data path reads it for every inbound packet. An atomic
// pointer rather than a mutex because the read side is the hot one and must
// never be made to wait on a policy change — a lock here would put the control
// plane's update latency directly into the packet path.
type Guard struct {
	filter atomic.Pointer[Filter]

	// dropped counts rejected packets. Worth having: "the policy is wrong" and
	// "the network is broken" look identical from inside an application, and
	// this is the only place that can tell them apart.
	dropped atomic.Uint64

	// flows are the conversations this machine started, so their replies can
	// be let back in. See NoteOutbound.
	flows flowTable
}

// NewGuard returns a guard that permits everything until a filter is set.
func NewGuard() *Guard { return &Guard{} }

// Set replaces the filter. A nil filter means allow-all.
func (g *Guard) Set(f *Filter) { g.filter.Store(f) }

// Dropped is how many packets the filter has rejected.
func (g *Guard) Dropped() uint64 { return g.dropped.Load() }

// Active reports whether a filter is being enforced.
func (g *Guard) Active() bool { return g.filter.Load() != nil }

// NoteOutbound records a packet this machine is sending into the tunnel, so
// that the reply to it is let back in.
//
// Rules are directional — "the laptop may reach the server's ssh" — and a
// filter that only judged each inbound packet on its own would refuse the
// server's answer, which arrives at the laptop from a port no rule names. The
// connection would open on the server and hang on the laptop. Remembering
// what was sent is what makes a one-way rule mean what it says; it is also
// what brings the internet's answers back through an exit node under a policy
// that grants the internet and nothing else.
//
// Called for every packet the host sends into the tunnel, so it has to be
// cheap. Nothing is recorded while no filter is set, since nothing would be
// refused.
func (g *Guard) NoteOutbound(packet []byte) {
	if g.filter.Load() == nil {
		return
	}
	p, ok := parsePacket(packet)
	if !ok || p.fragment {
		return
	}
	switch p.proto {
	case protoTCP, protoUDP:
		g.flows.note(flowKey{proto: p.proto, local: p.src, remote: p.dst, lport: p.sport, rport: p.dport})
	case protoICMP, protoICMP6:
		if p.icmpEchoRequest() {
			g.flows.note(flowKey{proto: p.proto, local: p.src, remote: p.dst})
		}
	}
}

// AllowInbound reports whether a decrypted packet may be delivered to the host.
//
// Called for every packet coming out of the tunnel. A malformed or
// unparseable packet is dropped: the alternative is to pass something we could
// not classify, which is exactly the case a filter exists to prevent.
func (g *Guard) AllowInbound(packet []byte) bool {
	f := g.filter.Load()
	if f == nil {
		return true
	}

	p, ok := parsePacket(packet)
	if !ok {
		g.dropped.Add(1)
		return false
	}

	var allowed bool
	if (p.proto == protoTCP || p.proto == protoUDP) && !p.fragment {
		allowed = f.Allow(p.src, p.dst, p.dport)
	} else {
		allowed = f.AllowNonTransport(p.src, p.dst)
	}
	if !allowed {
		allowed = g.isReply(p)
	}
	if !allowed {
		g.dropped.Add(1)
	}
	return allowed
}

// isReply reports whether an inbound packet answers something this machine
// sent: the other half of a TCP or UDP conversation it started, the echo of
// its ping, or an error a router sent back about one of its packets — which
// is how path-MTU discovery works, and why dropping those would make a
// connection that mostly works stall on its first large write.
func (g *Guard) isReply(p packet) bool {
	if p.fragment {
		return false
	}
	switch p.proto {
	case protoTCP, protoUDP:
		return g.flows.has(flowKey{proto: p.proto, local: p.dst, remote: p.src, lport: p.dport, rport: p.sport})
	case protoICMP, protoICMP6:
		if p.icmpEchoReply() {
			return g.flows.has(flowKey{proto: p.proto, local: p.dst, remote: p.src})
		}
		if inner, ok := p.icmpError(); ok && inner.src == p.dst {
			switch inner.proto {
			case protoTCP, protoUDP:
				return g.flows.has(flowKey{proto: inner.proto, local: inner.src, remote: inner.dst, lport: inner.sport, rport: inner.dport})
			case protoICMP, protoICMP6:
				return g.flows.has(flowKey{proto: inner.proto, local: inner.src, remote: inner.dst})
			}
		}
	}
	return false
}

// --- flows -------------------------------------------------------------

// flowKey is one conversation, from this machine's side.
type flowKey struct {
	proto         uint8
	local, remote netip.Addr
	lport, rport  uint16
}

// maxFlows bounds the table. A browser behind an exit node keeps a few
// hundred conversations open; this is far above that and still small. When
// it is full the conversation touched longest ago is forgotten, which costs
// at worst a reply dropped on a connection nobody has used in a long while.
const maxFlows = 8192

// flowTable remembers conversations by recency rather than by timer. A timer
// would expire an idle ssh session whose server then prints something, and
// the output would be dropped until somebody typed; least-recently-used only
// forgets what the table has no room for.
type flowTable struct {
	mu  sync.Mutex
	m   map[flowKey]*list.Element
	lru list.List
}

func (t *flowTable) note(k flowKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = make(map[flowKey]*list.Element)
	}
	if e, ok := t.m[k]; ok {
		t.lru.MoveToFront(e)
		return
	}
	t.m[k] = t.lru.PushFront(k)
	if t.lru.Len() > maxFlows {
		oldest := t.lru.Back()
		t.lru.Remove(oldest)
		delete(t.m, oldest.Value.(flowKey))
	}
}

func (t *flowTable) has(k flowKey) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[k]
	if ok {
		t.lru.MoveToFront(e)
	}
	return ok
}

// --- parsing -----------------------------------------------------------

const (
	protoICMP  = 1
	protoTCP   = 6
	protoUDP   = 17
	protoICMP6 = 58
)

// packet is what a filter decision needs from one IP packet.
type packet struct {
	src, dst     netip.Addr
	proto        uint8
	sport, dport uint16

	// fragment marks a non-initial IPv4 fragment, which carries no transport
	// header and so no ports.
	fragment bool

	// payload is what follows the IP header: the ICMP message, for ICMP.
	payload []byte
}

// ipv6Extension lists the IPv6 next-header values that are another header
// rather than the payload. Walking the chain would be a second protocol stack
// in the data path, so a packet that starts one is refused instead; judging
// it as "no ports" would let a TCP segment behind a hop-by-hop header past
// every port rule.
var ipv6Extension = map[uint8]bool{
	0: true, 43: true, 44: true, 51: true, 60: true, 135: true, 139: true, 140: true, 253: true, 254: true,
}

// parsePacket extracts the fields a filter decision needs.
//
// Deliberately minimal: enough of IPv4 and IPv6 to find the addresses and,
// for TCP and UDP, the ports. Anything more — options, extension header
// chains, reassembly — would be a second protocol stack in the data path, and
// the packets that need it are rare enough to be denied rather than parsed.
func parsePacket(b []byte) (p packet, ok bool) {
	if len(b) < 1 {
		return
	}

	var rest []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return
		}
		p.proto = b[9]
		p.src = netip.AddrFrom4([4]byte(b[12:16]))
		p.dst = netip.AddrFrom4([4]byte(b[16:20]))

		// A non-zero fragment offset means the transport header is in the
		// first fragment, not this one. Judging it on addresses alone is the
		// only honest option, and it is why the filter has a ports-less path.
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			p.fragment = true
			return p, true
		}
		rest = b[ihl:]

	case 6:
		if len(b) < 40 {
			return
		}
		p.proto = b[6]
		p.src = netip.AddrFrom16([16]byte(b[8:24]))
		p.dst = netip.AddrFrom16([16]byte(b[24:40]))
		if ipv6Extension[p.proto] {
			return packet{}, false
		}
		rest = b[40:]

	default:
		return
	}

	p.payload = rest
	if p.proto == protoTCP || p.proto == protoUDP {
		if len(rest) >= 4 {
			p.sport = binary.BigEndian.Uint16(rest[0:2])
			p.dport = binary.BigEndian.Uint16(rest[2:4])
		}
	}
	return p, true
}

// icmpEchoRequest reports whether p is a ping.
func (p packet) icmpEchoRequest() bool {
	if len(p.payload) < 1 {
		return false
	}
	return (p.proto == protoICMP && p.payload[0] == 8) || (p.proto == protoICMP6 && p.payload[0] == 128)
}

// icmpEchoReply reports whether p answers a ping.
func (p packet) icmpEchoReply() bool {
	if len(p.payload) < 1 {
		return false
	}
	return (p.proto == protoICMP && p.payload[0] == 0) || (p.proto == protoICMP6 && p.payload[0] == 129)
}

// icmpError returns the packet an ICMP error is about — the start of which it
// quotes after its own eight-byte header — when p is one.
func (p packet) icmpError() (packet, bool) {
	if len(p.payload) < 8 {
		return packet{}, false
	}
	t := p.payload[0]
	isErr := (p.proto == protoICMP && (t == 3 || t == 11 || t == 12)) ||
		(p.proto == protoICMP6 && t >= 1 && t <= 4)
	if !isErr {
		return packet{}, false
	}
	return parsePacket(p.payload[8:])
}
