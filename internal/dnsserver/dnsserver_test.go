package dnsserver

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/netmap"
)

// askFor builds a DNS query the way a resolver would.
func askFor(name string, qtype uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], 0x1234)
	binary.BigEndian.PutUint16(b[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(b[4:6], 1)      // one question

	for _, label := range strings.Split(strings.Trim(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	return binary.BigEndian.AppendUint16(b, 1) // class IN
}

func rcode(resp []byte) uint16 { return binary.BigEndian.Uint16(resp[2:4]) & 0x000f }

func answerCount(resp []byte) uint16 { return binary.BigEndian.Uint16(resp[6:8]) }

// firstAnswerA reads the address out of the first answer record.
func firstAnswerA(t *testing.T, resp []byte) netip.Addr {
	t.Helper()

	// Skip the header and the echoed question to reach the answer.
	i := 12
	for resp[i] != 0 {
		i += int(resp[i]) + 1
	}
	i += 1 + 4 // terminating zero, then qtype and qclass

	// The answer: a two-byte compression pointer, type, class, ttl, length.
	i += 2 + 2 + 2 + 4
	length := int(binary.BigEndian.Uint16(resp[i : i+2]))
	i += 2

	if length != 4 {
		t.Fatalf("answer rdata is %d bytes, want 4", length)
	}
	addr, _ := netip.AddrFromSlice(resp[i : i+4])
	return addr
}

func testServer(t *testing.T) *Server {
	t.Helper()

	s := &Server{
		forward: make(map[string]netip.Addr),
		reverse: make(map[netip.Addr]string),
	}
	s.SetRecords("makima",
		netmap.Node{Name: "laptop", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}},
		[]netmap.Node{
			{Name: "desktop", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}},
			{Name: "Justin's NAS", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")}},
		})
	return s
}

func TestResolvesAPeer(t *testing.T) {
	s := testServer(t)

	resp, err := s.respond(askFor("desktop.makima", typeA))
	if err != nil {
		t.Fatal(err)
	}
	if rcode(resp) != rcodeNoError {
		t.Fatalf("rcode %d, want NOERROR", rcode(resp))
	}
	if answerCount(resp) != 1 {
		t.Fatalf("%d answers, want 1", answerCount(resp))
	}

	got := firstAnswerA(t, resp)
	if got.String() != "100.64.0.2" {
		t.Errorf("desktop.makima resolved to %s, want 100.64.0.2", got)
	}
}

func TestResolvesSelf(t *testing.T) {
	s := testServer(t)

	resp, err := s.respond(askFor("laptop.makima", typeA))
	if err != nil {
		t.Fatal(err)
	}
	if answerCount(resp) != 1 {
		t.Fatal("a node cannot resolve its own name")
	}
}

// A name outside the mesh domain must be REFUSED, which tells the resolver to
// ask its real server. Answering would make this an open resolver.
func TestForeignNameIsRefused(t *testing.T) {
	s := testServer(t)

	resp, err := s.respond(askFor("example.com", typeA))
	if err != nil {
		t.Fatal(err)
	}
	if rcode(resp) != rcodeRefused {
		t.Errorf("rcode %d for a name outside the mesh, want REFUSED", rcode(resp))
	}
}

// A name inside the mesh domain that is not a node gets NXDOMAIN: this server
// is authoritative there, and REFUSED would send the resolver to the public
// internet with a private name.
func TestUnknownMeshNameIsNXDomain(t *testing.T) {
	s := testServer(t)

	resp, err := s.respond(askFor("nosuch.makima", typeA))
	if err != nil {
		t.Fatal(err)
	}
	if rcode(resp) != rcodeNXDomain {
		t.Errorf("rcode %d for an unknown mesh name, want NXDOMAIN", rcode(resp))
	}
}

// Mesh addresses are IPv4 only. NXDOMAIN for AAAA would make a dual-stack
// resolver conclude the name does not exist and never try the A record.
func TestAAAAIsEmptyNotNXDomain(t *testing.T) {
	s := testServer(t)

	resp, err := s.respond(askFor("desktop.makima", typeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if rcode(resp) != rcodeNoError {
		t.Errorf("rcode %d for AAAA, want NOERROR with no answers", rcode(resp))
	}
	if answerCount(resp) != 0 {
		t.Errorf("%d answers for AAAA, want 0", answerCount(resp))
	}
}

func TestReverseLookup(t *testing.T) {
	s := testServer(t)

	resp, err := s.respond(askFor("2.0.64.100.in-addr.arpa", typePTR))
	if err != nil {
		t.Fatal(err)
	}
	if rcode(resp) != rcodeNoError || answerCount(resp) != 1 {
		t.Fatalf("reverse lookup gave rcode %d with %d answers", rcode(resp), answerCount(resp))
	}
	if !strings.Contains(string(resp), "desktop") {
		t.Error("the PTR answer does not name the node")
	}
}

// firstAnswerName reads the name out of the first answer record, as a PTR
// carries it.
func firstAnswerName(t *testing.T, resp []byte) string {
	t.Helper()

	i := 12
	for resp[i] != 0 {
		i += int(resp[i]) + 1
	}
	i += 1 + 4
	i += 2 + 2 + 2 + 4
	length := int(binary.BigEndian.Uint16(resp[i : i+2]))
	i += 2
	rdata := resp[i : i+length]

	var labels []string
	for j := 0; j < len(rdata) && rdata[j] != 0; j += int(rdata[j]) + 1 {
		labels = append(labels, string(rdata[j+1:j+1+int(rdata[j])]))
	}
	return strings.Join(labels, ".")
}

// The reverse answer used to carry the node's raw name, so the NAS came back
// as "Justin's NAS.makima": not a valid hostname, and not the name
// justins-nas.makima that resolves to it. Anything checking one against the
// other — sshd with UseDNS, say — found them disagreeing.
func TestReverseLookupAnswersTheForwardName(t *testing.T) {
	s := testServer(t)

	resp, err := s.respond(askFor("3.0.64.100.in-addr.arpa", typePTR))
	if err != nil {
		t.Fatal(err)
	}
	if answerCount(resp) != 1 {
		t.Fatalf("reverse lookup gave %d answers, want 1", answerCount(resp))
	}
	if got := firstAnswerName(t, resp); got != "justins-nas.makima" {
		t.Errorf("100.64.0.3 reverses to %q, want justins-nas.makima", got)
	}
}

// Two nodes whose names come out as the same label cannot both have it. The
// one that lost the forward name must not keep answering reverse lookups with
// it: that name resolves to the other machine.
func TestReverseLookupNeverNamesAnotherMachine(t *testing.T) {
	s := &Server{}
	s.SetRecords("makima",
		netmap.Node{Name: "laptop", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}},
		[]netmap.Node{
			{Name: "web server", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")}},
			{Name: "web_server", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.6/32")}},
		})

	resp, err := s.respond(askFor("web-server.makima", typeA))
	if err != nil {
		t.Fatal(err)
	}
	owner := firstAnswerA(t, resp)
	other := netip.MustParseAddr("100.64.0.5")
	if owner == other {
		other = netip.MustParseAddr("100.64.0.6")
	}

	o := other.As4()
	arpa := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", o[3], o[2], o[1], o[0])
	resp, err = s.respond(askFor(arpa, typePTR))
	if err != nil {
		t.Fatal(err)
	}
	if answerCount(resp) != 0 {
		t.Errorf("%s reverses to %q, which resolves to %s", other, firstAnswerName(t, resp), owner)
	}
}

// Mesh addresses are IPv4 today, but nothing in a netmap node's type says so.
// An A answer for an IPv6 address used to panic in the resolver's goroutine,
// which ends the whole daemon.
func TestANodeWithoutAnIPv4AddressDoesNotCrashTheResolver(t *testing.T) {
	s := &Server{}
	s.SetRecords("makima",
		netmap.Node{Name: "six", Addresses: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::1/128")}},
		nil)

	resp, err := s.respond(askFor("six.makima", typeA))
	if err != nil {
		t.Fatal(err)
	}
	if rcode(resp) != rcodeNoError || answerCount(resp) != 0 {
		t.Errorf("rcode %d with %d answers, want NOERROR with none: the name exists, without an IPv4 address",
			rcode(resp), answerCount(resp))
	}
}

func TestReverseLookupOfUnknownAddress(t *testing.T) {
	s := testServer(t)

	resp, err := s.respond(askFor("99.0.64.100.in-addr.arpa", typePTR))
	if err != nil {
		t.Fatal(err)
	}
	if rcode(resp) != rcodeNXDomain {
		t.Errorf("rcode %d for an unknown address, want NXDOMAIN", rcode(resp))
	}
}

// Hostnames routinely contain characters DNS does not allow. Rewriting rather
// than rejecting means the machine still gets a usable name.
func TestNameNormalisation(t *testing.T) {
	cases := map[string]string{
		"laptop":           "laptop",
		"Justin's MacBook": "justins-macbook",
		"web_server.local": "web-server-local",
		"---":              "",
		"UPPER":            "upper",
		"has spaces":       "has-spaces",
	}
	for in, want := range cases {
		if got := normaliseName(in); got != want {
			t.Errorf("normaliseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalisedNameIsResolvable(t *testing.T) {
	s := testServer(t)

	resp, err := s.respond(askFor("justins-nas.makima", typeA))
	if err != nil {
		t.Fatal(err)
	}
	if answerCount(resp) != 1 {
		t.Fatal("a node whose name needed normalising is not resolvable")
	}
	if got := firstAnswerA(t, resp); got.String() != "100.64.0.3" {
		t.Errorf("resolved to %s, want 100.64.0.3", got)
	}
}

func TestMalformedQueriesRejected(t *testing.T) {
	s := testServer(t)

	for _, b := range [][]byte{nil, {1, 2, 3}, make([]byte, 12)} {
		if _, err := s.respond(b); err == nil {
			t.Errorf("a %d-byte malformed query produced an answer", len(b))
		}
	}
}

// A compression pointer cannot appear in a question — there is nothing earlier
// to point at — so following one would be chasing an attacker's offset.
func TestCompressionPointerInQuestionRejected(t *testing.T) {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[4:6], 1)
	b = append(b, 0xc0, 0x0c) // a pointer where a label length belongs

	if _, err := parseQuery(b); err == nil {
		t.Error("a question containing a compression pointer was parsed")
	}
}

func TestArpaToAddr(t *testing.T) {
	got, ok := arpaToAddr("2.0.64.100.in-addr.arpa")
	if !ok || got.String() != "100.64.0.2" {
		t.Errorf("arpaToAddr gave %s (ok=%v), want 100.64.0.2", got, ok)
	}

	for _, bad := range []string{"example.com", "1.2.3.in-addr.arpa", "256.0.64.100.in-addr.arpa"} {
		if _, ok := arpaToAddr(bad); ok {
			t.Errorf("arpaToAddr(%q) succeeded", bad)
		}
	}
}

// A DNS label holds at most 63 bytes, and a hostname can be longer. The label
// used to be the whole name, which no query can carry, so the machine had no
// working name — and its reverse answer dropped the label and named the bare
// domain. It is cut to fit instead.
func TestALongNameStillGetsAWorkingLabel(t *testing.T) {
	long := "the-build-machine-in-the-back-office-that-nobody-remembers-setting-up"
	s := &Server{}
	s.SetRecords("makima",
		netmap.Node{Name: long, Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")}},
		nil)

	label := Label(long)
	if len(label) > 63 || !strings.HasPrefix(long, label) || strings.HasSuffix(label, "-") {
		t.Fatalf("label %q (%d bytes) is not the name cut to fit", label, len(label))
	}

	resp, err := s.respond(askFor(label+".makima", typeA))
	if err != nil {
		t.Fatal(err)
	}
	if answerCount(resp) != 1 || firstAnswerA(t, resp).String() != "100.64.0.9" {
		t.Errorf("%s.makima did not resolve to the machine", label)
	}

	resp, err = s.respond(askFor("9.0.64.100.in-addr.arpa", typePTR))
	if err != nil {
		t.Fatal(err)
	}
	if got := firstAnswerName(t, resp); got != label+".makima" {
		t.Errorf("100.64.0.9 reverses to %q, want %s.makima", got, label)
	}
}
