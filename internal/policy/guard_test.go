package policy

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// flowPacket is an IPv4 TCP or UDP packet with both ports set.
func flowPacket(src, dst netip.Addr, proto uint8, sport, dport uint16) []byte {
	b := ipv4Packet(src, dst, proto, dport)
	binary.BigEndian.PutUint16(b[20:22], sport)
	return b
}

func icmpPacket(src, dst netip.Addr, typ byte, quoted []byte) []byte {
	b := make([]byte, 20+8+len(quoted))
	b[0] = 0x45
	b[9] = protoICMP
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	b[20] = typ
	copy(b[28:], quoted)
	return b
}

// oneWay lets the laptop reach the server's ssh and says nothing about the
// other direction — which is the shape of nearly every real rule.
func oneWay(t *testing.T) (*Guard, netip.Addr, netip.Addr) {
	t.Helper()
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"laptop"}, Dst: []string{"server:22"}},
	}}
	g := NewGuard()
	g.Set(p.CompileFor(laptop, []Node{laptop, server}))
	return g, laptop.Addresses[0].Addr(), server.Addresses[0].Addr()
}

// The laptop's own filter has no rule that admits anything from the server,
// so before the guard remembered what it sent, the server's answer to the
// laptop's ssh was dropped: the connection opened on one end and hung on the
// other.
func TestReplyToWhatThisMachineStartedIsLetIn(t *testing.T) {
	g, me, srv := oneWay(t)

	g.NoteOutbound(flowPacket(me, srv, protoTCP, 53211, 22))
	if !g.AllowInbound(flowPacket(srv, me, protoTCP, 22, 53211)) {
		t.Error("the server's answer to our ssh was dropped")
	}
}

func TestUnsolicitedPacketIsStillRefused(t *testing.T) {
	g, me, srv := oneWay(t)

	g.NoteOutbound(flowPacket(me, srv, protoTCP, 53211, 22))
	for _, pkt := range [][]byte{
		flowPacket(srv, me, protoTCP, 22, 53212), // another port of ours
		flowPacket(srv, me, protoTCP, 23, 53211), // another port of theirs
		flowPacket(srv, me, protoUDP, 22, 53211), // another protocol
		flowPacket(srv, me, protoTCP, 5000, 80),  // nothing we started
	} {
		if g.AllowInbound(pkt) {
			t.Errorf("admitted a packet nothing here asked for: %v", pkt[:24])
		}
	}
}

// An exit node's user under "autogroup:internet" only: the internet answers
// from addresses no rule could name, and those answers have to get back.
func TestInternetAnswersComeBack(t *testing.T) {
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"mac"}, Dst: []string{Internet + ":*"}},
	}}
	g := NewGuard()
	g.Set(p.CompileFor(mac, []Node{mac, exitNode}))
	me := mac.Addresses[0].Addr()
	site := netip.MustParseAddr("93.184.216.34")

	g.NoteOutbound(flowPacket(me, site, protoTCP, 40000, 443))
	if !g.AllowInbound(flowPacket(site, me, protoTCP, 443, 40000)) {
		t.Error("the website's answer was dropped")
	}
}

// A router on the way telling us a packet was too big is how path-MTU
// discovery works. It comes from the router, not from the peer, so it can
// only be recognised by the packet it quotes.
func TestErrorAboutOurPacketIsLetIn(t *testing.T) {
	g, me, srv := oneWay(t)
	ours := flowPacket(me, srv, protoTCP, 53211, 22)
	g.NoteOutbound(ours)

	router := netip.MustParseAddr("203.0.113.1")
	if !g.AllowInbound(icmpPacket(router, me, 3, ours[:28])) {
		t.Error("an ICMP error about our own connection was dropped")
	}

	theirs := flowPacket(me, srv, protoTCP, 1, 2)
	if g.AllowInbound(icmpPacket(router, me, 3, theirs[:28])) {
		t.Error("an ICMP error about a connection we never made was admitted")
	}
}

func TestPingReplyIsLetIn(t *testing.T) {
	g, me, srv := oneWay(t)
	if g.AllowInbound(icmpPacket(srv, me, 0, nil)) {
		t.Fatal("an echo reply to nothing was admitted")
	}
	g.NoteOutbound(icmpPacket(me, srv, 8, nil))
	if !g.AllowInbound(icmpPacket(srv, me, 0, nil)) {
		t.Error("the answer to our ping was dropped")
	}
}

// Nothing is recorded while no filter is set, so a node that has not been
// given a policy pays nothing for this on its outbound path.
func TestNothingRecordedWithoutAFilter(t *testing.T) {
	g := NewGuard()
	g.NoteOutbound(flowPacket(netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("10.77.0.2"), protoTCP, 1, 2))
	if g.flows.lru.Len() != 0 {
		t.Error("a guard with no filter recorded a flow")
	}
}

func TestFlowTableForgetsTheOldestWhenFull(t *testing.T) {
	var ft flowTable
	a, b := netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("10.77.0.2")
	first := flowKey{proto: protoTCP, local: a, remote: b, lport: 1, rport: 1}
	ft.note(first)
	for i := range maxFlows {
		ft.note(flowKey{proto: protoUDP, local: a, remote: b, lport: uint16(i), rport: 2})
	}
	if ft.has(first) {
		t.Error("the table grew past its bound instead of forgetting the oldest flow")
	}
	if ft.lru.Len() != maxFlows || len(ft.m) != maxFlows {
		t.Errorf("table holds %d/%d, want %d", ft.lru.Len(), len(ft.m), maxFlows)
	}
}

// A TCP segment behind an IPv6 extension header used to be judged as though
// it had no ports, and so passed any rule that let the two hosts speak at all.
func TestIPv6ExtensionHeaderIsRefused(t *testing.T) {
	p := &Policy{ACLs: []Rule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{"*:22"}},
	}}
	v6 := Node{Name: "v6", Addresses: []netip.Prefix{netip.MustParsePrefix("2001:db8::2/128")}}
	g := NewGuard()
	g.Set(p.CompileFor(v6, []Node{v6}))

	b := make([]byte, 40+8+8)
	b[0] = 0x60
	b[6] = 0 // hop-by-hop options, with TCP to port 80 behind it
	copy(b[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(b[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	b[40] = protoTCP
	binary.BigEndian.PutUint16(b[50:52], 80)

	if g.AllowInbound(b) {
		t.Error("a TCP segment behind a hop-by-hop header got past a rule for port 22 only")
	}
}
