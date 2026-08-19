package control

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
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
}

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
}

// AuthKey is a single credential for joining the mesh.
type AuthKey struct {
	Secret   string        `json:"secret"`
	Reusable bool          `json:"reusable"`
	Expires  time.Time     `json:"expires"`
	Used     bool          `json:"used"`
	UsedBy   netmap.NodeID `json:"used_by,omitempty"`
	Created  time.Time     `json:"created"`
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
		existing.NodeKey = req.NodeKey
		existing.DiscoKey = req.DiscoKey
		existing.Endpoints = req.Endpoints
		existing.LastSeen = now
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
		ID:         netmap.NodeID(s.state.NextID),
		Name:       req.Name,
		MachineKey: machineKey,
		NodeKey:    req.NodeKey,
		DiscoKey:   req.DiscoKey,
		Address:    addr,
		Endpoints:  req.Endpoints,
		Created:    now,
		LastSeen:   now,
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
// Every node currently sees every other node. That is where the ACL policy
// engine plugs in later: this function becomes the place a compiled packet
// filter trims the peer list, and nothing else has to change.
func (s *Store) NetMapFor(machineKey key.Public) (*MapResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	self := s.findByMachineKey(machineKey)
	if self == nil {
		return nil, fmt.Errorf("unknown machine key")
	}

	resp := &MapResponse{
		Version: s.version,
		Self:    self.toNetmapNode(),
		Peers:   make([]netmap.Node, 0, len(s.state.Nodes)-1),
	}
	for _, n := range s.state.Nodes {
		if n.ID == self.ID {
			continue
		}
		resp.Peers = append(resp.Peers, n.toNetmapNode())
	}
	return resp, nil
}

func (n *Node) toNetmapNode() netmap.Node {
	return netmap.Node{
		ID:        n.ID,
		Name:      n.Name,
		Key:       n.NodeKey,
		Addresses: []netip.Prefix{n.Address},
		Endpoints: n.Endpoints,
	}
}

// MintAuthKey creates a join credential. A zero ttl means it never expires.
//
// A negative ttl is refused rather than clamped. The obvious implementation
// only sets an expiry when ttl > 0, which turns `-expiry -1h` — a plausible
// typo — into a credential that is valid forever, failing in the most
// permissive direction available.
func (s *Store) MintAuthKey(reusable bool, ttl time.Duration) (*AuthKey, error) {
	if ttl < 0 {
		return nil, fmt.Errorf("auth key lifetime cannot be negative (got %s); pass 0 for a key that never expires", ttl)
	}

	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("read entropy: %w", err)
	}

	a := &AuthKey{
		Secret:   "makima_" + base64.RawURLEncoding.EncodeToString(raw[:]),
		Reusable: reusable,
		Created:  time.Now().UTC(),
	}
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
