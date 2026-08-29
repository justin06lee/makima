package policy

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func node(name string, addr string, tags ...string) Node {
	return Node{
		Name:      name,
		Tags:      tags,
		Addresses: []netip.Prefix{netip.MustParsePrefix(addr)},
	}
}

var (
	laptop  = node("laptop", "100.64.0.1/32")
	server  = node("server", "100.64.0.2/32", "server")
	printer = node("printer", "100.64.0.3/32", "iot")
)

func TestDefaultPolicyAllowsEverything(t *testing.T) {
	p := DefaultPolicy()

	if !p.CanSee(laptop, printer) {
		t.Error("the default policy hid a peer")
	}

	f := p.CompileFor(server, []Node{laptop, server, printer})
	if !f.Allow(laptop.Addresses[0].Addr(), server.Addresses[0].Addr(), 22) {
		t.Error("the default policy blocked a packet")
	}
}

// The point of a policy: a node that no rule mentions is not merely blocked,
// it is never named in anyone's netmap.
func TestUnmentionedNodeIsInvisible(t *testing.T) {
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"laptop"}, Dst: []string{"tag:server:*"}},
	}}

	if !p.CanSee(laptop, server) {
		t.Error("laptop cannot see the server it is allowed to reach")
	}
	if p.CanSee(laptop, printer) {
		t.Error("laptop can see a printer no rule mentions")
	}
}

// Visibility has to be symmetric even though rules are directional: WireGuard
// cannot establish a session unless both ends hold the other's key.
func TestVisibilityIsSymmetric(t *testing.T) {
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"laptop"}, Dst: []string{"server:22"}},
	}}

	if !p.CanSee(laptop, server) {
		t.Error("the initiator cannot see the responder")
	}
	if !p.CanSee(server, laptop) {
		t.Error("the responder cannot see the initiator, so no session could ever start")
	}
}

func TestPortRestriction(t *testing.T) {
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{"server:22"}},
	}}

	f := p.CompileFor(server, []Node{laptop, server})
	src := laptop.Addresses[0].Addr()
	dst := server.Addresses[0].Addr()

	if !f.Allow(src, dst, 22) {
		t.Error("ssh was blocked by a rule that permits it")
	}
	if f.Allow(src, dst, 80) {
		t.Error("http was permitted by a rule that only names port 22")
	}
}

func TestPortRanges(t *testing.T) {
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{"server:8000-8100"}},
	}}

	f := p.CompileFor(server, []Node{laptop, server})
	src := laptop.Addresses[0].Addr()
	dst := server.Addresses[0].Addr()

	for _, port := range []uint16{8000, 8050, 8100} {
		if !f.Allow(src, dst, port) {
			t.Errorf("port %d is in the range but was blocked", port)
		}
	}
	for _, port := range []uint16{7999, 8101} {
		if f.Allow(src, dst, port) {
			t.Errorf("port %d is outside the range but was permitted", port)
		}
	}
}

func TestGroups(t *testing.T) {
	p := &Policy{
		Groups: map[string][]string{"group:trusted": {"laptop"}},
		ACLs: []Rule{
			{Action: "accept", Src: []string{"group:trusted"}, Dst: []string{"tag:server:*"}},
		},
	}

	if !p.CanSee(laptop, server) {
		t.Error("a group member cannot see its destination")
	}
	if p.CanSee(printer, server) {
		t.Error("a non-member can see a destination reserved for the group")
	}

	f := p.CompileFor(server, []Node{laptop, server, printer})
	if !f.Allow(laptop.Addresses[0].Addr(), server.Addresses[0].Addr(), 443) {
		t.Error("a group member's packet was blocked")
	}
	if f.Allow(printer.Addresses[0].Addr(), server.Addresses[0].Addr(), 443) {
		t.Error("a non-member's packet was permitted")
	}
}

// ICMP has no ports. Dropping it would break path-MTU discovery and make a
// working mesh feel mysteriously broken.
func TestNonTransportAllowedBetweenPermittedHosts(t *testing.T) {
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"laptop"}, Dst: []string{"server:22"}},
	}}

	f := p.CompileFor(server, []Node{laptop, server})
	if !f.AllowNonTransport(laptop.Addresses[0].Addr(), server.Addresses[0].Addr()) {
		t.Error("ICMP between two hosts that may speak was dropped")
	}
	if f.AllowNonTransport(printer.Addresses[0].Addr(), server.Addresses[0].Addr()) {
		t.Error("ICMP from a host with no rule was permitted")
	}
}

// A nil filter means the control plane sent none, which must not sever a node
// from the mesh it already knows.
func TestNilFilterAllows(t *testing.T) {
	var f *Filter
	if !f.Allow(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), 22) {
		t.Error("a nil filter blocked traffic")
	}
	if !f.AllowNonTransport(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")) {
		t.Error("a nil filter blocked ICMP")
	}
}

func TestValidateRejectsBadPolicies(t *testing.T) {
	cases := []struct {
		name string
		p    *Policy
	}{
		{"deny action", &Policy{ACLs: []Rule{{Action: "deny", Src: []string{"*"}, Dst: []string{"*:*"}}}}},
		{"no src", &Policy{ACLs: []Rule{{Action: "accept", Dst: []string{"*:*"}}}}},
		{"no dst", &Policy{ACLs: []Rule{{Action: "accept", Src: []string{"*"}}}}},
		{"backwards range", &Policy{ACLs: []Rule{{Action: "accept", Src: []string{"*"}, Dst: []string{"server:100-1"}}}}},
		{"bad group name", &Policy{Groups: map[string][]string{"trusted": {"laptop"}}}},
	}
	for _, c := range cases {
		if err := c.p.Validate(); err == nil {
			t.Errorf("%s: accepted an invalid policy", c.name)
		}
	}

	good := &Policy{
		Groups: map[string][]string{"group:ops": {"laptop"}},
		ACLs:   []Rule{{Action: "accept", Src: []string{"group:ops"}, Dst: []string{"server:22", "printer:*"}}},
	}
	if err := good.Validate(); err != nil {
		t.Errorf("a valid policy was rejected: %v", err)
	}
}

// An entity may itself contain colons. Splitting from the left would turn an
// IPv6 prefix into a malformed port.
func TestSplitDstPort(t *testing.T) {
	cases := []struct {
		in     string
		entity string
		first  uint16
		last   uint16
	}{
		{"server:22", "server", 22, 22},
		{"server:*", "server", 0, 65535},
		{"server", "server", 0, 65535},
		{"server:100-200", "server", 100, 200},
		{"10.0.0.0/8:443", "10.0.0.0/8", 443, 443},
		{"fd00::/8", "fd00::/8", 0, 65535},
	}
	for _, c := range cases {
		entity, pr, err := splitDstPort(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if entity != c.entity {
			t.Errorf("%q: entity %q, want %q", c.in, entity, c.entity)
		}
		if pr.First != c.first || pr.Last != c.last {
			t.Errorf("%q: ports %d-%d, want %d-%d", c.in, pr.First, pr.Last, c.first, c.last)
		}
	}
}

// A rule can name a machine by address without knowing its name.
func TestCIDRSource(t *testing.T) {
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"192.168.1.0/24"}, Dst: []string{"server:*"}},
	}}

	f := p.CompileFor(server, []Node{server})
	if !f.Allow(netip.MustParseAddr("192.168.1.50"), server.Addresses[0].Addr(), 80) {
		t.Error("a packet from the permitted subnet was blocked")
	}
	if f.Allow(netip.MustParseAddr("192.168.2.50"), server.Addresses[0].Addr(), 80) {
		t.Error("a packet from outside the subnet was permitted")
	}
}

// --- packet parsing -----------------------------------------------------

func ipv4Packet(src, dst netip.Addr, proto uint8, dstPort uint16) []byte {
	b := make([]byte, 20+8)
	b[0] = 0x45 // version 4, IHL 5
	b[9] = proto
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(b[22:24], dstPort)
	return b
}

func TestGuardFiltersByPort(t *testing.T) {
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{"server:22"}},
	}}

	g := NewGuard()
	g.Set(p.CompileFor(server, []Node{laptop, server}))

	src := laptop.Addresses[0].Addr()
	dst := server.Addresses[0].Addr()

	if !g.AllowInbound(ipv4Packet(src, dst, protoTCP, 22)) {
		t.Error("ssh was dropped")
	}
	if g.AllowInbound(ipv4Packet(src, dst, protoTCP, 80)) {
		t.Error("http was delivered")
	}
	if g.Dropped() != 1 {
		t.Errorf("dropped counter is %d, want 1", g.Dropped())
	}
}

func TestGuardAllowsWithoutFilter(t *testing.T) {
	g := NewGuard()
	if g.Active() {
		t.Error("a guard with no filter reports itself active")
	}
	if !g.AllowInbound(ipv4Packet(
		netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), protoTCP, 22)) {
		t.Error("a guard with no filter dropped a packet")
	}
}

// A packet that cannot be classified must be dropped, not passed: passing
// something unparseable is precisely what a filter exists to prevent.
func TestGuardDropsMalformedPackets(t *testing.T) {
	g := NewGuard()
	g.Set(&Filter{})

	for _, b := range [][]byte{nil, {0x45}, {0xff, 0xff}, make([]byte, 10)} {
		if g.AllowInbound(b) {
			t.Errorf("a malformed %d-byte packet was delivered", len(b))
		}
	}
}

// A non-initial fragment has no transport header. Judging it on addresses
// alone is the only honest option.
func TestFragmentJudgedByAddress(t *testing.T) {
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"laptop"}, Dst: []string{"server:22"}},
	}}

	g := NewGuard()
	g.Set(p.CompileFor(server, []Node{laptop, server}))

	pkt := ipv4Packet(laptop.Addresses[0].Addr(), server.Addresses[0].Addr(), protoTCP, 9999)
	binary.BigEndian.PutUint16(pkt[6:8], 0x0001) // non-zero fragment offset

	if !g.AllowInbound(pkt) {
		t.Error("a fragment between two permitted hosts was dropped")
	}
}

func TestParseIPv6Packet(t *testing.T) {
	b := make([]byte, 40+8)
	b[0] = 0x60
	b[6] = protoTCP
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("2001:db8::2")
	copy(b[8:24], src.AsSlice())
	copy(b[24:40], dst.AsSlice())
	binary.BigEndian.PutUint16(b[42:44], 443)

	gotSrc, gotDst, proto, port, ok := parsePacket(b)
	if !ok {
		t.Fatal("a well-formed IPv6 packet did not parse")
	}
	if gotSrc != src || gotDst != dst {
		t.Error("addresses did not survive parsing")
	}
	if proto != protoTCP || port != 443 {
		t.Errorf("proto %d port %d, want %d 443", proto, port, protoTCP)
	}
}
