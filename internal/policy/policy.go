// Package policy decides who may talk to whom.
//
// The policy is written once, centrally, and enforced in two different places
// for two different reasons.
//
// The control plane applies it when it builds a netmap, so a node is never
// even told about a peer it may not reach. That is not merely tidy: a key and
// an address it never receives are a key and an address it cannot misuse, and
// the smallest netmap that still works is the smallest blast radius when a
// node is compromised.
//
// The node applies the compiled filter to inbound packets, because the netmap
// can only express whole-peer visibility while a real policy wants ports. Two
// nodes that may exchange SSH but not everything else must still hold each
// other's keys, so the finer decision has to happen where the packets are.
//
// Enforcement is on ingress rather than egress. A sender that has been
// compromised will not enforce anything against itself, so the only check that
// means anything is the one the receiver makes.
package policy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Node is the subset of a machine's record that policy decisions depend on.
//
// Deliberately a plain struct rather than the control plane's own type: policy
// is evaluated on the server and enforced on the node, and neither should have
// to import the other's storage model to do it.
type Node struct {
	Name      string
	Tags      []string
	Addresses []netip.Prefix

	// Routes are the subnets this node has been approved to route, which are
	// reachable *through* it and therefore addressable by policy.
	Routes []netip.Prefix
}

// Policy is the access-control document.
//
// The shape is deliberately close to Tailscale's, because the shape is good
// and because anyone who has written one before should not have to learn a
// second dialect to write this one.
type Policy struct {
	// Groups name sets of nodes, so a rule can say "the servers" instead of
	// listing them and going stale the moment one is added.
	Groups map[string][]string `json:"groups,omitempty"`

	// ACLs are evaluated in order, though order does not currently matter:
	// every rule is an accept, and there is no deny. Default-deny plus
	// accept-only rules is the one arrangement where reading the policy top to
	// bottom tells you what is allowed, with no need to hold earlier rules in
	// your head to understand a later one.
	ACLs []Rule `json:"acls"`
}

// Rule permits traffic from a set of sources to a set of destinations.
type Rule struct {
	// Action is always "accept". The field exists so a deny could be added
	// later without changing the file format, and is validated so a policy
	// that says "deny" fails loudly rather than silently permitting.
	Action string `json:"action"`

	// Src entities: "*", "group:name", "tag:name", a node name, or a CIDR.
	Src []string `json:"src"`

	// Dst entities with an optional port suffix: "tag:server:22",
	// "10.0.0.0/8:*", "*:*". A destination without a port means all ports.
	Dst []string `json:"dst"`
}

// DefaultPolicy is what a mesh with no policy file does: everyone may reach
// everyone, which is the only sane default for the machines one person owns.
func DefaultPolicy() *Policy {
	return &Policy{
		ACLs: []Rule{{Action: "accept", Src: []string{"*"}, Dst: []string{"*:*"}}},
	}
}

// PortRange is an inclusive range of destination ports.
type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

// AllPorts matches every port.
var AllPorts = PortRange{First: 0, Last: 65535}

// Contains reports whether p is in the range.
func (r PortRange) Contains(p uint16) bool { return p >= r.First && p <= r.Last }

// Match is one compiled allow rule: traffic from any of Srcs, to any of Dsts,
// on any of Ports.
type Match struct {
	Srcs  []netip.Prefix `json:"srcs"`
	Dsts  []netip.Prefix `json:"dsts"`
	Ports []PortRange    `json:"ports"`
}

// Filter is the compiled, node-local half of a policy: what this node accepts
// on ingress.
//
// A nil Filter means "no policy was compiled", which is treated as allow-all.
// That is the correct failure direction here and only here: a filter is
// distributed by the control plane, and a node that loses contact with it must
// keep working with the mesh it already knows rather than silently severing
// itself.
type Filter struct {
	Matches []Match `json:"matches"`
}

// Validate reports whether the policy is well-formed.
//
// Called before a policy is ever stored, so a typo is rejected while an
// operator is looking at the error rather than discovered as an outage.
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	for name := range p.Groups {
		if !strings.HasPrefix(name, "group:") {
			return fmt.Errorf("group %q must be named \"group:something\"", name)
		}
	}
	for i, r := range p.ACLs {
		if r.Action != "accept" {
			return fmt.Errorf("acl %d: action is %q; only \"accept\" is supported", i, r.Action)
		}
		if len(r.Src) == 0 {
			return fmt.Errorf("acl %d: no src", i)
		}
		if len(r.Dst) == 0 {
			return fmt.Errorf("acl %d: no dst", i)
		}
		for _, d := range r.Dst {
			if _, _, err := splitDstPort(d); err != nil {
				return fmt.Errorf("acl %d: dst %q: %w", i, d, err)
			}
		}
	}
	return nil
}

// CanSee reports whether node a should be told about node b.
//
// Visibility is symmetric even though the rules are directional, and it has to
// be: WireGuard cannot establish a session unless both ends hold the other's
// key. A one-way rule that hid the initiator from the responder would permit a
// conversation neither side could actually start.
func (p *Policy) CanSee(a, b Node) bool {
	if p == nil {
		return true
	}
	return p.allowsAny(a, b) || p.allowsAny(b, a)
}

// allowsAny reports whether any rule permits src to reach dst on any port.
func (p *Policy) allowsAny(src, dst Node) bool {
	for _, r := range p.ACLs {
		if !p.matchesEntity(r.Src, src) {
			continue
		}
		for _, d := range r.Dst {
			entity, _, err := splitDstPort(d)
			if err != nil {
				continue
			}
			if p.matchesEntityOne(entity, dst) {
				return true
			}
		}
	}
	return false
}

// CompileFor renders the policy into the filter a node enforces on ingress.
//
// The result names addresses, never identities: the node has to evaluate it
// per packet, and resolving a name or a tag at that point would mean carrying
// the whole mesh's membership into the data path.
func (p *Policy) CompileFor(self Node, all []Node) *Filter {
	if p == nil {
		return nil
	}

	f := &Filter{}
	for _, r := range p.ACLs {
		// Only the parts of the rule that name *this* node as a destination
		// matter; the rest is somebody else's ingress problem.
		var ports []PortRange
		var dsts []netip.Prefix

		for _, d := range r.Dst {
			entity, pr, err := splitDstPort(d)
			if err != nil {
				continue
			}
			if !p.matchesEntityOne(entity, self) {
				continue
			}
			dsts = appendPrefixes(dsts, prefixesOf(self))
			ports = appendPort(ports, pr)
		}
		if len(dsts) == 0 {
			continue
		}

		var srcs []netip.Prefix
		for _, s := range r.Src {
			srcs = appendPrefixes(srcs, p.resolveToPrefixes(s, all))
		}
		if len(srcs) == 0 {
			continue
		}

		f.Matches = append(f.Matches, Match{Srcs: srcs, Dsts: dsts, Ports: ports})
	}
	return f
}

// Allow reports whether an inbound packet is permitted.
//
// A nil filter allows everything; see the note on Filter for why that is the
// right direction to fail in.
func (f *Filter) Allow(src, dst netip.Addr, port uint16) bool {
	if f == nil {
		return true
	}
	for _, m := range f.Matches {
		if !containsAddr(m.Srcs, src) {
			continue
		}
		if !containsAddr(m.Dsts, dst) {
			continue
		}
		for _, pr := range m.Ports {
			if pr.Contains(port) {
				return true
			}
		}
	}
	return false
}

// AllowNonTransport reports whether a packet with no ports — ICMP, or a
// fragment whose header we never saw — is permitted between two addresses.
//
// Judged on addresses alone. Dropping all ICMP would break path-MTU discovery
// and make a mesh that mostly works feel mysteriously broken, so a protocol
// without ports is allowed whenever any rule permits the two hosts to speak at
// all.
func (f *Filter) AllowNonTransport(src, dst netip.Addr) bool {
	if f == nil {
		return true
	}
	for _, m := range f.Matches {
		if containsAddr(m.Srcs, src) && containsAddr(m.Dsts, dst) {
			return true
		}
	}
	return false
}

// --- entity resolution -------------------------------------------------

func (p *Policy) matchesEntity(entities []string, n Node) bool {
	for _, e := range entities {
		if p.matchesEntityOne(e, n) {
			return true
		}
	}
	return false
}

func (p *Policy) matchesEntityOne(entity string, n Node) bool {
	switch {
	case entity == "*":
		return true

	case strings.HasPrefix(entity, "tag:"):
		want := strings.TrimPrefix(entity, "tag:")
		for _, t := range n.Tags {
			if t == want {
				return true
			}
		}
		return false

	case strings.HasPrefix(entity, "group:"):
		for _, member := range p.Groups[entity] {
			if p.matchesEntityOne(member, n) {
				return true
			}
		}
		return false
	}

	if entity == n.Name {
		return true
	}

	// A literal address or prefix matches a node that owns it, so a rule can
	// name a machine by IP without knowing what it was called.
	if pfx, err := parsePrefix(entity); err == nil {
		for _, a := range prefixesOf(n) {
			if pfx.Overlaps(a) {
				return true
			}
		}
	}
	return false
}

// resolveToPrefixes turns a source entity into the addresses it covers.
func (p *Policy) resolveToPrefixes(entity string, all []Node) []netip.Prefix {
	switch {
	case entity == "*":
		// Anything, including addresses reached through a subnet router, which
		// is why this is not simply the mesh range.
		return []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}

	case strings.HasPrefix(entity, "group:"):
		var out []netip.Prefix
		for _, member := range p.Groups[entity] {
			out = appendPrefixes(out, p.resolveToPrefixes(member, all))
		}
		return out
	}

	if pfx, err := parsePrefix(entity); err == nil {
		return []netip.Prefix{pfx}
	}

	var out []netip.Prefix
	for _, n := range all {
		if p.matchesEntityOne(entity, n) {
			out = appendPrefixes(out, prefixesOf(n))
		}
	}
	return out
}

// splitDstPort separates "entity:ports" into its halves.
//
// The entity may itself contain colons — an IPv6 prefix does — so the split is
// from the right, and a trailing component that does not parse as a port is
// treated as part of the entity rather than as a malformed port.
func splitDstPort(d string) (entity string, pr PortRange, err error) {
	i := strings.LastIndex(d, ":")
	if i < 0 {
		return d, AllPorts, nil
	}

	head, tail := d[:i], d[i+1:]
	if tail == "*" {
		return head, AllPorts, nil
	}

	if lo, hi, ok := strings.Cut(tail, "-"); ok {
		a, err1 := strconv.ParseUint(lo, 10, 16)
		b, err2 := strconv.ParseUint(hi, 10, 16)
		if err1 != nil || err2 != nil {
			return "", PortRange{}, fmt.Errorf("%q is not a port range", tail)
		}
		if a > b {
			return "", PortRange{}, fmt.Errorf("port range %q runs backwards", tail)
		}
		return head, PortRange{First: uint16(a), Last: uint16(b)}, nil
	}

	n, convErr := strconv.ParseUint(tail, 10, 16)
	if convErr != nil {
		// Not a port at all. An entity like "fd00::/8" ends in something that
		// is not a number, and treating that as an error would reject a
		// perfectly good rule.
		return d, AllPorts, nil
	}
	return head, PortRange{First: uint16(n), Last: uint16(n)}, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func prefixesOf(n Node) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(n.Addresses)+len(n.Routes))
	out = append(out, n.Addresses...)
	out = append(out, n.Routes...)
	return out
}

func appendPrefixes(dst, src []netip.Prefix) []netip.Prefix {
	for _, p := range src {
		found := false
		for _, e := range dst {
			if e == p {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, p)
		}
	}
	return dst
}

func appendPort(dst []PortRange, p PortRange) []PortRange {
	for _, e := range dst {
		if e == p {
			return dst
		}
	}
	return append(dst, p)
}

func containsAddr(prefixes []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
