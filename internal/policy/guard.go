package policy

import (
	"encoding/binary"
	"net/netip"
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
}

// NewGuard returns a guard that permits everything until a filter is set.
func NewGuard() *Guard { return &Guard{} }

// Set replaces the filter. A nil filter means allow-all.
func (g *Guard) Set(f *Filter) { g.filter.Store(f) }

// Dropped is how many packets the filter has rejected.
func (g *Guard) Dropped() uint64 { return g.dropped.Load() }

// Active reports whether a filter is being enforced.
func (g *Guard) Active() bool { return g.filter.Load() != nil }

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

	src, dst, proto, port, ok := parsePacket(packet)
	if !ok {
		g.dropped.Add(1)
		return false
	}

	var allowed bool
	if proto == protoTCP || proto == protoUDP {
		allowed = f.Allow(src, dst, port)
	} else {
		allowed = f.AllowNonTransport(src, dst)
	}
	if !allowed {
		g.dropped.Add(1)
	}
	return allowed
}

const (
	protoICMP  = 1
	protoTCP   = 6
	protoUDP   = 17
	protoICMP6 = 58
)

// parsePacket extracts the fields a filter decision needs.
//
// Deliberately minimal: enough of IPv4 and IPv6 to find the addresses and, for
// TCP and UDP, the destination port. Anything more — options, extension header
// chains, reassembly — would be a second protocol stack in the data path, and
// the packets that need it are rare enough to be denied rather than parsed.
func parsePacket(b []byte) (src, dst netip.Addr, proto uint8, port uint16, ok bool) {
	if len(b) < 1 {
		return
	}

	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return
		}
		proto = b[9]
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))

		// A non-zero fragment offset means the transport header is in the
		// first fragment, not this one. Judging it on addresses alone is the
		// only honest option, and it is why the filter has a ports-less path.
		fragOffset := binary.BigEndian.Uint16(b[6:8]) & 0x1fff
		if fragOffset != 0 {
			return src, dst, protoICMP, 0, true
		}

		port, _ = transportPort(proto, b[ihl:])
		return src, dst, proto, port, true

	case 6:
		if len(b) < 40 {
			return
		}
		proto = b[6]
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		port, _ = transportPort(proto, b[40:])
		return src, dst, proto, port, true
	}
	return
}

func transportPort(proto uint8, rest []byte) (uint16, bool) {
	switch proto {
	case protoTCP, protoUDP:
		if len(rest) < 4 {
			return 0, false
		}
		return binary.BigEndian.Uint16(rest[2:4]), true
	}
	return 0, false
}
