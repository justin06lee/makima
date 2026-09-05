package control

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/policy"
)

// State is everything the control plane knows, and the whole of what must
// survive a restart.
//
// It is a JSON file rather than a database. At the scale this serves — the
// machines one person owns — a table engine buys nothing and costs the pure-Go
// cross-compilation that lets a single `make cross` produce binaries for five
// platforms. The file is also readable and editable by hand, which matters
// more than query planning when the thing you need at 2am is to see why a node
// was handed the wrong address.
type State struct {
	// ServerKey is the control plane's own identity. Nodes seal their
	// requests to its public half.
	ServerKey key.Private `json:"server_key"`

	// Prefix is the range addresses are allocated from.
	Prefix netip.Prefix `json:"prefix"`

	Nodes    []*Node    `json:"nodes"`
	AuthKeys []*AuthKey `json:"auth_keys"`
	NextID   uint64     `json:"next_id"`

	// Relays are the mesh's relays, in preference order.
	//
	// Every node is assigned the same one. That is not a simplification to be
	// fixed later but a consequence of what a relay is: two nodes can only
	// meet on a relay they are both connected to, and this relay does not
	// forward to other relays. A list therefore means failover, not load
	// spreading — the server picks one, and because the choice travels in the
	// netmap, the whole mesh moves together or not at all.
	Relays []netmap.Relay `json:"relays,omitempty"`

	// Domain is the DNS suffix mesh names live under.
	Domain string `json:"domain,omitempty"`

	// DNSEnabled turns on name resolution mesh-wide.
	DNSEnabled bool `json:"dns_enabled,omitempty"`

	// Policy is the access-control policy. A nil policy means the default:
	// every node may reach every other node.
	Policy *policy.Policy `json:"policy,omitempty"`

	// Lock is the network lock — the signing authority that lets nodes verify
	// each other's keys without trusting this server. Nil means disabled.
	Lock *Lock `json:"lock,omitempty"`
}

// DefaultDomain is the suffix mesh names live under when none is configured.
//
// Not a public TLD and not ".local", which mDNS already owns and which would
// make every mesh lookup race a multicast responder.
const DefaultDomain = "makima"

// Node is one registered machine.
type Node struct {
	ID         netmap.NodeID    `json:"id"`
	Name       string           `json:"name"`
	MachineKey key.Public       `json:"machine_key"`
	NodeKey    key.Public       `json:"node_key"`
	DiscoKey   key.Public       `json:"disco_key"`
	Address    netip.Prefix     `json:"address"`
	Endpoints  []netip.AddrPort `json:"endpoints,omitempty"`
	Created    time.Time        `json:"created"`
	LastSeen   time.Time        `json:"last_seen"`

	// AdvertisedRoutes are subnets this node has offered to route for the
	// mesh. Offering is not enabling: a node can claim any prefix it likes,
	// including one that would hijack the whole internet, so nothing is
	// installed anywhere until an operator approves it.
	AdvertisedRoutes []netip.Prefix `json:"advertised_routes,omitempty"`

	// ExitRevoked records that an operator withdrew this node's exit-node
	// approval on purpose. An offer is otherwise accepted as it arrives —
	// see Register — and without this a revoke would be undone the next time
	// the node checked in.
	ExitRevoked bool `json:"exit_revoked,omitempty"`

	// ApprovedRoutes are the subset an operator has accepted. Only these
	// appear in anyone's netmap.
	ApprovedRoutes []netip.Prefix `json:"approved_routes,omitempty"`

	// AdvertisesExit reports that this node has offered to carry general
	// internet traffic, and ExitApproved that an operator agreed.
	AdvertisesExit bool `json:"advertises_exit,omitempty"`
	ExitApproved   bool `json:"exit_approved,omitempty"`

	// Tags label a node for policy. A node's tags come from the auth key it
	// joined with, not from anything the node says about itself — otherwise a
	// node could grant itself whatever access the policy gives a tag.
	Tags []string `json:"tags,omitempty"`

	// KeySignature is the network lock's signature over this node's key,
	// present only once the lock is enabled and the node has been signed.
	KeySignature []byte `json:"key_signature,omitempty"`

	// KeyRotatedAt records the last node-key change, so an operator can see
	// which machines are overdue.
	KeyRotatedAt time.Time `json:"key_rotated_at,omitzero"`

	// Expired means the node must present a valid auth key again before it is
	// served another netmap. Set by an operator on a machine that may have
	// been lost, and cleared by a successful re-registration.
	Expired bool `json:"expired,omitempty"`

	// Services are the ports this node publishes, as it last reported them.
	Services []netmap.Service `json:"services,omitempty"`
}

// Online reports whether the node has polled recently enough to be considered
// present.
//
// The threshold is twice the poll heartbeat: one missed heartbeat is a network
// hiccup, two means the node is genuinely not talking to us.
func (n *Node) Online() bool {
	return !n.LastSeen.IsZero() && time.Since(n.LastSeen) < 2*pollTimeout
}

// AuthKey is a single credential for joining the mesh.
type AuthKey struct {
	Secret   string        `json:"secret"`
	Reusable bool          `json:"reusable"`
	Expires  time.Time     `json:"expires"`
	Used     bool          `json:"used"`
	UsedBy   netmap.NodeID `json:"used_by,omitempty"`
	Created  time.Time     `json:"created"`

	// Tags are applied to every node that joins with this key.
	//
	// Tagging via the credential rather than letting a node declare its own is
	// the only arrangement where a tag means anything: a node that could name
	// its own tags could grant itself whatever access the policy gives them.
	Tags []string `json:"tags,omitempty"`

	// Handle and MACKey exist for an invite given as words. The joining
	// machine, holding the words, asks for the server's key by handle; the
	// server answers with the key and a MAC over it under MACKey, which only
	// the words can derive. That is how fifteen words verify a server without
	// carrying its key. Both are derived from the words; the words themselves
	// are never stored anywhere.
	Handle string `json:"handle,omitempty"`
	MACKey []byte `json:"mac_key,omitempty"`
}

// Valid reports whether the key may still be redeemed.
func (a *AuthKey) Valid(now time.Time) bool {
	if !a.Expires.IsZero() && now.After(a.Expires) {
		return false
	}
	return a.Reusable || !a.Used
}

// Store is the persistent, concurrency-safe home of State.
type Store struct {
	mu    sync.Mutex
	path  string
	state *State

	// version increments on every change to the mesh. Long-polling nodes
	// compare against it to decide whether they are behind.
	version uint64

	// changed is closed and replaced on every change, so any number of
	// waiting pollers wake at once without the store tracking who they are.
	changed chan struct{}
}

// DefaultPrefix is where node addresses come from.
//
// Deliberately the low end of the CGNAT range: Tailscale hashes its
// allocations across the whole /10, so sequential allocation from the bottom
// keeps makima out of its way on a machine running both. Only /32 host routes
// are ever installed, so even a collision would be resolved by longest-prefix
// match rather than breaking either network.
var DefaultPrefix = netip.MustParsePrefix("100.64.0.0/10")

// OpenStore loads state from path, creating it — and the control plane's
// identity — on first run.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, changed: make(chan struct{})}

	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var st State
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		s.state = &st

	case os.IsNotExist(err):
		serverKey, err := key.NewPrivate()
		if err != nil {
			return nil, err
		}
		s.state = &State{
			ServerKey: serverKey,
			Prefix:    DefaultPrefix,
			NextID:    1,
		}
		if err := s.save(); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if !s.state.Prefix.IsValid() {
		s.state.Prefix = DefaultPrefix
	}
	if s.state.NextID == 0 {
		s.state.NextID = 1
	}
	return s, nil
}

// save writes state durably. Callers must hold the lock.
//
// Write-then-rename because a torn control file is not a recoverable state:
// every node's identity and address assignment lives here, and half a file
// means re-registering the entire mesh by hand.
func (s *Store) save() error {
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	b = append(b, '\n')

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".makima-state-*")
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp state: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state: %w", err)
	}
	return os.Rename(tmp.Name(), s.path)
}

// bump records a change and wakes every waiting poller. Callers must hold the
// lock.
func (s *Store) bump() {
	s.version++
	close(s.changed)
	s.changed = make(chan struct{})
}

// Changed returns a channel closed the next time the mesh changes.
//
// Take this *before* reading the current version, or a change landing between
// the read and the subscribe is missed and the poller sleeps through it.
func (s *Store) Changed() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}

// Version is the current netmap generation.
func (s *Store) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// ServerKey is the control plane's private identity.
func (s *Store) ServerKey() key.Private {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.ServerKey
}

// allocate finds the lowest unused address. Callers must hold the lock.
func (s *Store) allocate() (netip.Prefix, error) {
	used := make(map[netip.Addr]bool, len(s.state.Nodes))
	for _, n := range s.state.Nodes {
		used[n.Address.Addr()] = true
	}

	// Skip the network address itself; .0 is conventionally not handed out
	// and some stacks treat it specially.
	addr := s.state.Prefix.Addr().Next()
	for s.state.Prefix.Contains(addr) {
		if !used[addr] {
			return netip.PrefixFrom(addr, addr.BitLen()), nil
		}
		addr = addr.Next()
	}
	return netip.Prefix{}, fmt.Errorf("address range %s is exhausted", s.state.Prefix)
}

// Register adds a node, or updates one that already holds this machine key.
//
// Re-registration needs no auth key. The request arrived sealed under a
// machine key the server already knows, which is stronger proof of identity
// than a bearer token — it is how a node rotates its WireGuard key or reports
// a new name without an operator minting anything.
func (s *Store) Register(machineKey key.Public, req *RegisterRequest) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	if existing := s.findByMachineKey(machineKey); existing != nil {
		// An expired node has to prove itself again before anything else is
		// accepted from it, including a key rotation — otherwise "expire the
		// stolen laptop" would be undone by the laptop simply reconnecting.
		if existing.Expired {
			auth := s.findAuthKey(req.AuthKey)
			if auth == nil || !auth.Valid(now) {
				return nil, fmt.Errorf("node %q has been expired by an operator and needs a new auth key to rejoin", existing.Name)
			}
			auth.Used = true
			auth.UsedBy = existing.ID
			existing.Expired = false
			existing.Tags = auth.Tags
		}

		// A changed node key is a rotation. Recording when it happened is what
		// lets an operator see which machines are overdue, and dropping the
		// old signature is mandatory: the signature covers the old key and
		// would verify against nothing.
		if existing.NodeKey != req.NodeKey && !existing.NodeKey.IsZero() {
			existing.KeyRotatedAt = now
			existing.KeySignature = nil
		}

		existing.NodeKey = req.NodeKey
		existing.DiscoKey = req.DiscoKey
		existing.Endpoints = req.Endpoints
		existing.LastSeen = now
		existing.AdvertisedRoutes = req.AdvertiseRoutes
		existing.AdvertisesExit = req.AdvertiseExit
		existing.Services = req.Services
		if req.AdvertiseExit && !existing.ExitRevoked {
			existing.ExitApproved = true
		}

		// An approval only ever covers a route the node is still advertising.
		// Without this, a node could advertise 10.0.0.0/24, have it approved,
		// stop advertising it, and later have the stale approval reactivated
		// by re-advertising — approval granted once, applied forever.
		existing.ApprovedRoutes = intersect(existing.ApprovedRoutes, req.AdvertiseRoutes)
		if !req.AdvertiseExit {
			existing.ExitApproved = false
		}

		if req.Name != "" {
			existing.Name = req.Name
		}
		if err := s.save(); err != nil {
			return nil, err
		}
		s.bump()
		return existing, nil
	}

	auth := s.findAuthKey(req.AuthKey)
	if auth == nil || !auth.Valid(now) {
		return nil, fmt.Errorf("auth key is invalid, expired, or already used")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("node name is required")
	}

	addr, err := s.allocate()
	if err != nil {
		return nil, err
	}

	n := &Node{
		ID:               netmap.NodeID(s.state.NextID),
		Name:             req.Name,
		MachineKey:       machineKey,
		NodeKey:          req.NodeKey,
		DiscoKey:         req.DiscoKey,
		Address:          addr,
		Endpoints:        req.Endpoints,
		Created:          now,
		LastSeen:         now,
		Tags:             auth.Tags,
		AdvertisedRoutes: req.AdvertiseRoutes,
		AdvertisesExit:   req.AdvertiseExit,
		Services:         req.Services,
		// An exit-node offer is accepted as it arrives. Unlike a subnet route,
		// which every node installs the moment it is approved, an exit node
		// changes nothing until a person on another machine chooses it by
		// name — the decision is theirs, made in the open. Requiring an
		// operator to approve the offer first meant a command on a third
		// machine, and for a network of machines one person owns that was a
		// step with no decision in it. `makima-server routes revoke -exit`
		// still withdraws one, and stays withdrawn.
		ExitApproved: req.AdvertiseExit,
	}
	s.state.NextID++
	s.state.Nodes = append(s.state.Nodes, n)

	auth.Used = true
	auth.UsedBy = n.ID

	if err := s.save(); err != nil {
		return nil, err
	}
	s.bump()
	return n, nil
}

// UpdateEndpoints records where a node currently believes it is reachable.
//
// Returns whether anything actually changed: a node re-poll that reports the
// same endpoints must not bump the version, or every poll would wake every
// other node and the long-poll would degrade into a busy loop.
func (s *Store) UpdateEndpoints(machineKey key.Public, eps []netip.AddrPort) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := s.findByMachineKey(machineKey)
	if n == nil {
		return false, fmt.Errorf("unknown machine key")
	}
	n.LastSeen = time.Now().UTC()

	if sameEndpoints(n.Endpoints, eps) {
		return false, nil
	}
	n.Endpoints = eps
	if err := s.save(); err != nil {
		return false, err
	}
	s.bump()
	return true, nil
}

func sameEndpoints(a, b []netip.AddrPort) bool {
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

// NetMapFor builds one node's view of the mesh.
//
// This is where the policy engine lives. A node's netmap is not the mesh; it
// is the part of the mesh that node is allowed to see, and trimming it here
// rather than only at the packet filter means an unauthorised peer is never
// even named — no key, no address, nothing to attack.
func (s *Store) NetMapFor(machineKey key.Public) (*MapResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	self := s.findByMachineKey(machineKey)
	if self == nil {
		return nil, fmt.Errorf("unknown machine key")
	}

	relay := s.activeRelayLocked()

	resp := &MapResponse{
		Version:   s.version,
		Self:      s.toNetmapNode(self, relay),
		Peers:     make([]netmap.Node, 0, len(s.state.Nodes)-1),
		HomeRelay: relay,
		Domain:    s.domainLocked(),
		DNS: netmap.DNSConfig{
			Enabled: s.state.DNSEnabled,
			Domain:  s.domainLocked(),
		},
	}

	pol := s.policyLocked()
	selfNode := self.policyNode()

	// Every node, not just the visible ones: a rule whose source is a group
	// has to resolve to the addresses of every member, including members this
	// node cannot see. Their addresses appear in the filter, which is
	// unavoidable — a filter that named only visible peers could not express
	// "accept from the servers" at all.
	all := make([]policy.Node, 0, len(s.state.Nodes))
	for _, n := range s.state.Nodes {
		all = append(all, n.policyNode())
	}

	for _, n := range s.state.Nodes {
		if n.ID == self.ID {
			continue
		}
		if !pol.CanSee(selfNode, n.policyNode()) {
			continue
		}
		resp.Peers = append(resp.Peers, s.toNetmapNode(n, relay))
	}

	// The packet filter is the second half of the policy. The netmap decides
	// who a node may know about; this decides what may actually be sent to it,
	// which has to be enforced on the node because only the receiver can be
	// trusted to check.
	resp.Filter = pol.CompileFor(selfNode, all)

	if s.state.Lock != nil {
		resp.Lock = &LockConfig{
			Enabled:     s.state.Lock.Enabled,
			TrustedKeys: s.state.Lock.TrustedKeys,
		}
	}
	return resp, nil
}

// policyLocked returns the mesh's policy, or the permissive default.
func (s *Store) policyLocked() *policy.Policy {
	if s.state.Policy == nil {
		return policy.DefaultPolicy()
	}
	return s.state.Policy
}

// policyNode projects a stored node into what the policy engine needs.
//
// Tags come from the auth key the node joined with, never from the node
// itself. A node that could tag itself could grant itself whatever access a
// tag confers, which would make the policy advisory rather than enforced.
func (n *Node) policyNode() policy.Node {
	return policy.Node{
		Name:      n.Name,
		Tags:      n.Tags,
		Addresses: []netip.Prefix{n.Address},
		Routes:    n.ApprovedRoutes,
	}
}

// activeRelayLocked is the relay every node is currently assigned.
func (s *Store) activeRelayLocked() netmap.Relay {
	if len(s.state.Relays) == 0 {
		return netmap.Relay{}
	}
	return s.state.Relays[0]
}

func (s *Store) domainLocked() string {
	if s.state.Domain != "" {
		return s.state.Domain
	}
	return DefaultDomain
}

func (s *Store) toNetmapNode(n *Node, relay netmap.Relay) netmap.Node {
	out := netmap.Node{
		ID:           n.ID,
		Name:         n.Name,
		Key:          n.NodeKey,
		DiscoKey:     n.DiscoKey,
		Addresses:    []netip.Prefix{n.Address},
		Endpoints:    n.Endpoints,
		RelayURL:     relay.URL,
		Online:       n.Online(),
		KeySignature: n.KeySignature,
		Services:     n.Services,
	}

	// Only approved routes are ever published. An advertised-but-unapproved
	// route exists solely in the control plane's records, where an operator
	// can see it and decide.
	out.AllowedIPs = append(out.AllowedIPs, n.ApprovedRoutes...)
	if n.ExitApproved {
		out.AllowedIPs = append(out.AllowedIPs, exitRoutes()...)
	}
	return out
}

// exitRoutes are the two prefixes that together mean "all traffic".
//
// Expressed as two halves rather than 0.0.0.0/0 so they lose to any more
// specific route by longest-prefix match — including the host's own default
// route, which must keep working for the tunnel's own packets to get out.
func exitRoutes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
}

// intersect keeps only the prefixes present in both lists.
func intersect(a, b []netip.Prefix) []netip.Prefix {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	in := make(map[netip.Prefix]bool, len(b))
	for _, p := range b {
		in[p] = true
	}
	out := make([]netip.Prefix, 0, len(a))
	for _, p := range a {
		if in[p] {
			out = append(out, p)
		}
	}
	return out
}

// MintAuthKey creates a join credential. A zero ttl means it never expires.
//
// A negative ttl is refused rather than clamped. The obvious implementation
// only sets an expiry when ttl > 0, which turns `-expiry -1h` — a plausible
// typo — into a credential that is valid forever, failing in the most
// permissive direction available.
func (s *Store) MintAuthKey(reusable bool, ttl time.Duration) (*AuthKey, error) {
	return s.MintAuthKeyTagged(reusable, ttl, nil)
}

// MintAuthKeyTagged creates a credential that also assigns policy tags.
func (s *Store) MintAuthKeyTagged(reusable bool, ttl time.Duration, tags []string) (*AuthKey, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("read entropy: %w", err)
	}
	return s.mint(&AuthKey{
		Secret:   "makima_" + base64.RawURLEncoding.EncodeToString(raw[:]),
		Reusable: reusable,
		Tags:     tags,
	}, ttl)
}

// MintInviteKey stores a credential that was derived from words, together
// with the handle and MAC key derived from the same words. Single-use: an
// invite is for one machine.
func (s *Store) MintInviteKey(secret, handle string, macKey []byte, ttl time.Duration) (*AuthKey, error) {
	if !strings.HasPrefix(secret, "makima_") || len(secret) < 24 {
		return nil, fmt.Errorf("that is not an auth key")
	}
	if handle == "" || len(macKey) < 16 {
		return nil, fmt.Errorf("an invite key needs a handle and a MAC key")
	}
	return s.mint(&AuthKey{Secret: secret, Handle: handle, MACKey: macKey}, ttl)
}

func (s *Store) mint(a *AuthKey, ttl time.Duration) (*AuthKey, error) {
	if ttl < 0 {
		return nil, fmt.Errorf("auth key lifetime cannot be negative (got %s); pass 0 for a key that never expires", ttl)
	}
	a.Created = time.Now().UTC()
	if ttl > 0 {
		a.Expires = a.Created.Add(ttl)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.AuthKeys = append(s.state.AuthKeys, a)
	if err := s.save(); err != nil {
		return nil, err
	}
	return a, nil
}

// Nodes returns a snapshot of every registered node.
func (s *Store) Nodes() []Node {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Node, 0, len(s.state.Nodes))
	for _, n := range s.state.Nodes {
		out = append(out, *n)
	}
	return out
}

// Forget removes a node by name.
func (s *Store) Forget(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := s.state.Nodes[:0]
	found := false
	for _, n := range s.state.Nodes {
		if n.Name == name {
			found = true
			continue
		}
		kept = append(kept, n)
	}
	if !found {
		return fmt.Errorf("no node named %q", name)
	}
	s.state.Nodes = kept
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

func (s *Store) findByMachineKey(k key.Public) *Node {
	for _, n := range s.state.Nodes {
		if n.MachineKey == k {
			return n
		}
	}
	return nil
}

// InviteMAC vouches for the server's key to whoever holds the words behind a
// handle. Nothing for a handle that is unknown, spent or expired — the
// joining machine is told the invite is no good before it types anything
// else.
func (s *Store) InviteMAC(handle string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, a := range s.state.AuthKeys {
		if a.Handle == handle && a.Handle != "" && a.Valid(now) {
			m := hmac.New(sha256.New, a.MACKey)
			pub := s.state.ServerKey.Public()
			m.Write(pub[:])
			return m.Sum(nil), true
		}
	}
	return nil, false
}

func (s *Store) findAuthKey(secret string) *AuthKey {
	if secret == "" {
		return nil
	}
	for _, a := range s.state.AuthKeys {
		if a.Secret == secret {
			return a
		}
	}
	return nil
}
