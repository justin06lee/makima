package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

// The network lock closes the one hole the architecture otherwise leaves open.
//
// Everything else about this control plane is arranged so that compromising it
// buys an attacker as little as possible: it never sees a private key, never
// carries a packet, and cannot decrypt anything two nodes say to each other.
// What it *can* do is lie about membership — hand a node a peer that should
// not exist, whose traffic that node will then happily accept, because a
// netmap is simply believed.
//
// The lock removes that. Node keys are signed by an authority whose private
// half never touches the server, and every node verifies its peers' signatures
// against the trusted keys before admitting them to the data plane. A server
// that invents a peer now has to forge a signature it has no key for, and the
// invented peer is rejected by every node in the mesh.
//
// Which keys are trusted, and whether the lock is enforced at all, cannot be
// the server's to say either, or the server could simply switch the lock off
// or trust a key of its own. So every change to the lock is a statement —
// "version n: these keys, enforced or not" — signed by a key that version n-1
// trusted, and each node keeps the latest version it has accepted and moves
// forward only along that chain. The server carries the chain; it cannot
// write a link of it.

// SignatureVersion prefixes signed material so a signature can never be
// replayed into a different scheme.
const SignatureVersion = 1

// Lock is the mesh's signing authority.
type Lock struct {
	// TrustedKeys are the Ed25519 public keys whose signatures nodes accept.
	//
	// A list rather than a single key so an operator can rotate without a
	// flag day: publish the new key, wait for every node to have seen it, then
	// re-sign and drop the old one.
	TrustedKeys []SigningKey `json:"trusted_keys"`

	// Enabled gates enforcement. A lock can be configured and left off while
	// nodes are being signed, because turning it on before every node has a
	// signature would partition the mesh.
	Enabled bool `json:"enabled"`

	Created time.Time `json:"created"`

	// Chain is every version of the lock, oldest first, each signed by a key
	// the one before it trusted. The last is what Enabled and TrustedKeys
	// say. Empty for a lock set up before versions were signed.
	Chain []LockStatement `json:"chain,omitempty"`
}

// LockStatement is one version of the lock.
type LockStatement struct {
	Epoch   uint64   `json:"epoch"`
	Enabled bool     `json:"enabled"`
	Keys    [][]byte `json:"keys"`

	// Signer is the key that signed this version, and Sig its signature
	// over lockMaterial. For the first version the signer is one of its own
	// keys; after that, one of the previous version's.
	Signer []byte `json:"signer"`
	Sig    []byte `json:"sig"`
}

// lockMaterial is the exact bytes a lock statement's signature covers: a
// label no other signature in makima uses, the version, whether it is
// enforced, and the trusted keys in a fixed order. Names and dates are for
// people and are not covered.
func lockMaterial(epoch uint64, enabled bool, keys [][]byte) []byte {
	sorted := sortedKeys(keys)
	b := []byte("makima lock statement v1\x00")
	b = binary.BigEndian.AppendUint64(b, epoch)
	if enabled {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(sorted)))
	for _, k := range sorted {
		b = append(b, k...)
	}
	return b
}

func sortedKeys(keys [][]byte) [][]byte {
	out := make([][]byte, len(keys))
	copy(out, keys)
	slices.SortFunc(out, bytes.Compare)
	return out
}

// SignLockStatement makes the next version of the lock. Run wherever the
// signing key lives, which is not the control server.
func SignLockStatement(priv ed25519.PrivateKey, epoch uint64, enabled bool, keys [][]byte) LockStatement {
	keys = sortedKeys(keys)
	return LockStatement{
		Epoch:   epoch,
		Enabled: enabled,
		Keys:    keys,
		Signer:  priv.Public().(ed25519.PublicKey),
		Sig:     ed25519.Sign(priv, lockMaterial(epoch, enabled, keys)),
	}
}

// signedBy checks that st is signed by one of trusted.
func (st LockStatement) signedBy(trusted [][]byte) error {
	if len(st.Signer) != ed25519.PublicKeySize {
		return fmt.Errorf("lock version %d has no signer", st.Epoch)
	}
	if len(st.Keys) == 0 {
		// Nothing could ever sign the version after it: the lock would be
		// stuck there for good, on every node that took it.
		return fmt.Errorf("lock version %d trusts no key", st.Epoch)
	}
	if !containsKey(trusted, st.Signer) {
		return fmt.Errorf("lock version %d is signed by a key the version before it did not trust", st.Epoch)
	}
	for _, k := range st.Keys {
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("lock version %d names a key of %d bytes", st.Epoch, len(k))
		}
	}
	if !ed25519.Verify(ed25519.PublicKey(st.Signer), lockMaterial(st.Epoch, st.Enabled, st.Keys), st.Sig) {
		return fmt.Errorf("lock version %d's signature does not verify", st.Epoch)
	}
	return nil
}

func containsKey(keys [][]byte, k []byte) bool {
	for _, x := range keys {
		if bytes.Equal(x, k) {
			return true
		}
	}
	return false
}

// AdvanceLock moves a node's pinned lock along the chain the control plane
// sent, as far as the chain is signed, and returns where it got to.
//
// With no pin yet the node takes the first version on trust, provided it is
// signed by one of its own keys — the same trust it placed in this control
// plane when it joined, and no more. From then on each version has to be
// signed by a key the previous one trusted, so a control plane that turns
// against the network can offer nothing the node will take: not a lock
// switched off, not a key of its own, not a chain it wrote from scratch.
//
// Versions the node already has are skipped; a chain that breaks is followed
// up to the break, and the error says where.
func AdvanceLock(pin *netmap.LockPin, chain []LockStatement) (*netmap.LockPin, error) {
	cur := pin
	for _, st := range chain {
		if cur != nil && st.Epoch <= cur.Epoch {
			continue
		}
		var trusted [][]byte
		switch {
		case cur != nil:
			if st.Epoch != cur.Epoch+1 {
				return cur, fmt.Errorf("lock version %d follows %d; the versions between are missing", st.Epoch, cur.Epoch)
			}
			trusted = cur.Keys
		default:
			trusted = st.Keys
		}
		if err := st.signedBy(trusted); err != nil {
			return cur, err
		}
		cur = &netmap.LockPin{Epoch: st.Epoch, Enabled: st.Enabled, Keys: sortedKeys(st.Keys)}
	}
	return cur, nil
}

// VerifyPinned checks a node key's signature against a pinned lock. Nil when
// the pin does not enforce.
func VerifyPinned(pin *netmap.LockPin, id netmap.NodeID, nodeKey key.Public, sig []byte) error {
	if pin == nil || !pin.Enabled {
		return nil
	}
	l := &Lock{Enabled: true}
	for _, k := range pin.Keys {
		l.TrustedKeys = append(l.TrustedKeys, SigningKey{Public: k})
	}
	return l.VerifyNodeKey(id, nodeKey, sig)
}

// SigningKey is one trusted authority.
type SigningKey struct {
	// Public is the Ed25519 verification key.
	Public []byte `json:"public"`

	// Name is a human label, so `makima-server lock status` can say which
	// laptop holds the private half.
	Name string `json:"name"`

	Added time.Time `json:"added"`
}

// ID is a short, stable handle for a signing key.
func (s SigningKey) ID() string {
	enc := base64.RawURLEncoding.EncodeToString(s.Public)
	if len(enc) > 12 {
		return enc[:12]
	}
	return enc
}

// ErrLockDisabled reports an operation that needs a lock the mesh does not
// have.
var ErrLockDisabled = errors.New("network lock is not enabled on this mesh")

// signingMaterial is the exact bytes a node-key signature covers.
//
// The node ID is included alongside the key, and that pairing is the whole
// point: signing a bare key would let a compromised server move a legitimately
// signed key onto a different node record and reassign its address, so the
// signature has to bind the key to the identity it was issued for.
//
// A version prefix and a fixed-length, unambiguous encoding mean two different
// (id, key) pairs can never produce the same message to sign.
func signingMaterial(id netmap.NodeID, nodeKey key.Public) []byte {
	b := make([]byte, 0, 1+8+key.Size)
	b = append(b, byte(SignatureVersion))
	for i := 7; i >= 0; i-- {
		b = append(b, byte(id>>(uint(i)*8)))
	}
	b = append(b, nodeKey[:]...)
	return b
}

// SignNodeKey produces a signature binding a node key to a node ID.
//
// Run wherever the private key lives, which is deliberately not here: the
// signing key's whole value is that the control server never holds it.
func SignNodeKey(priv ed25519.PrivateKey, id netmap.NodeID, nodeKey key.Public) []byte {
	return ed25519.Sign(priv, signingMaterial(id, nodeKey))
}

// VerifyNodeKey checks a signature against every trusted key.
//
// Returns nil when the lock is disabled: a mesh that has not opted in is not
// broken, it has simply chosen to trust its control plane, which is the
// situation every mesh starts in.
func (l *Lock) VerifyNodeKey(id netmap.NodeID, nodeKey key.Public, sig []byte) error {
	if l == nil || !l.Enabled {
		return nil
	}
	if len(sig) == 0 {
		return fmt.Errorf("node %d has no key signature and the network lock is enabled", id)
	}

	msg := signingMaterial(id, nodeKey)
	for _, k := range l.TrustedKeys {
		if len(k.Public) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(k.Public), msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("node %d's key signature is not from any trusted key", id)
}

// Trusts reports whether a public key is already trusted.
func (l *Lock) Trusts(pub []byte) bool {
	if l == nil {
		return false
	}
	for _, k := range l.TrustedKeys {
		if len(k.Public) == len(pub) && string(k.Public) == string(pub) {
			return true
		}
	}
	return false
}

// --- store operations ---------------------------------------------------

// LockStatus is a snapshot for the CLI.
type LockStatus struct {
	Enabled     bool         `json:"enabled"`
	TrustedKeys []SigningKey `json:"trusted_keys"`
	Signed      int          `json:"signed"`
	Unsigned    int          `json:"unsigned"`
	Created     time.Time    `json:"created,omitzero"`

	// Epoch is the lock's current version, zero for a lock whose versions
	// were never signed — which nodes cannot hold the server to.
	Epoch uint64 `json:"epoch"`
}

// LockStatus reports the lock's state and how much of the mesh is signed.
func (s *Store) LockStatus() LockStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	st := LockStatus{}
	if s.state.Lock != nil {
		st.Enabled = s.state.Lock.Enabled
		st.TrustedKeys = s.state.Lock.TrustedKeys
		st.Created = s.state.Lock.Created
		if n := len(s.state.Lock.Chain); n > 0 {
			st.Epoch = s.state.Lock.Chain[n-1].Epoch
		}
	}
	for _, n := range s.state.Nodes {
		if s.signedLocked(n) {
			st.Signed++
		} else {
			st.Unsigned++
		}
	}
	return st
}

// signedLocked reports whether a node's signature is one the lock's current
// keys verify — not merely present: one left from a lock that was forgotten,
// or from a key since dropped, signs nothing now. Callers hold s.mu.
func (s *Store) signedLocked(n *Node) bool {
	if len(n.KeySignature) == 0 || s.state.Lock == nil {
		return false
	}
	l := &Lock{Enabled: true, TrustedKeys: s.state.Lock.TrustedKeys}
	return l.VerifyNodeKey(n.ID, n.NodeKey, n.KeySignature) == nil
}

// ApplyLockStatement makes st the lock's next version.
//
// The server checks what every node will check — the version follows the
// last, and is signed by a key the last one trusted, or for the first by one
// of its own — so a mistake is an error here rather than a version every node
// ignores. It also refuses a version that would partition the network: one
// enforced while some node has no signature from a key it trusts, which the
// whole mesh would then reject, including the machine somebody is sitting at.
//
// names labels keys that are new, by SigningKey.ID; keys already trusted keep
// their names.
func (s *Store) ApplyLockStatement(st LockStatement, names map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	l := s.state.Lock
	var prev [][]byte
	var want uint64 = 1
	switch {
	case l != nil && len(l.Chain) > 0:
		last := l.Chain[len(l.Chain)-1]
		prev, want = last.Keys, last.Epoch+1
	case l != nil && len(l.TrustedKeys) > 0:
		// A lock from before versions were signed. Its first signed version
		// has to come from a key it already trusts, or sealing it would be
		// a way to swap the keys unannounced.
		for _, k := range l.TrustedKeys {
			prev = append(prev, k.Public)
		}
		if !containsKey(prev, st.Signer) {
			return fmt.Errorf("the first signed version of this lock has to be signed by a key it already trusts")
		}
		if !containsKey(st.Keys, st.Signer) {
			return fmt.Errorf("the first version of a lock has to be signed by one of its own keys")
		}
		prev = st.Keys
	default:
		prev = st.Keys
	}
	if st.Epoch != want {
		return fmt.Errorf("this is lock version %d, but the next version is %d — somebody else changed the lock; try again", st.Epoch, want)
	}
	if err := st.signedBy(prev); err != nil {
		return err
	}
	if st.Enabled {
		if len(st.Keys) == 0 {
			return fmt.Errorf("a lock that trusts no key cannot be enforced")
		}
		pin := &netmap.LockPin{Epoch: st.Epoch, Enabled: true, Keys: st.Keys}
		var rejected []string
		for _, n := range s.state.Nodes {
			if VerifyPinned(pin, n.ID, n.NodeKey, n.KeySignature) != nil {
				rejected = append(rejected, n.Name)
			}
		}
		if len(rejected) > 0 {
			return fmt.Errorf("these nodes have no signature from a key this version trusts, and would be rejected by the whole mesh: %v\nsign them first with 'makima-server lock sign'", rejected)
		}
	}

	now := time.Now().UTC()
	if l == nil {
		l = &Lock{Created: now}
		s.state.Lock = l
	}
	var trusted []SigningKey
	for _, k := range sortedKeys(st.Keys) {
		sk := SigningKey{Public: k, Added: now}
		for _, old := range l.TrustedKeys {
			if bytes.Equal(old.Public, k) {
				sk = old
			}
		}
		if name, ok := names[sk.ID()]; ok && sk.Name == "" {
			sk.Name = name
		}
		trusted = append(trusted, sk)
	}
	l.TrustedKeys = trusted
	l.Enabled = st.Enabled
	l.Chain = append(l.Chain, st)

	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// ForgetLock throws the lock away, for a network whose every signing key is
// lost. A node that holds the lock goes on enforcing it — that is the point
// of nodes holding it — until somebody with root there runs
// `makima lock reset`; after that it sees no lock, and admits everyone.
//
// The nodes' signatures are kept. A node still holding the lock checks its
// peers against them, and wiping them would have every such node refuse
// every peer on its next netmap — including the peers somebody would have to
// reach, over makima, to run the reset. Signatures no longer verified by
// the lock's keys count as unsigned (see PendingSignatures).
func (s *Store) ForgetLock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Lock == nil {
		return ErrLockDisabled
	}
	s.state.Lock = nil
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// LockChain is the lock's signed versions, for the command line to build the
// next one on.
func (s *Store) LockChain() []LockStatement {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Lock == nil {
		return nil
	}
	return append([]LockStatement(nil), s.state.Lock.Chain...)
}

// UnsignedNodes lists nodes that still need a signature, with the exact
// material to sign.
type UnsignedNode struct {
	ID       netmap.NodeID `json:"id"`
	Name     string        `json:"name"`
	NodeKey  key.Public    `json:"node_key"`
	Material []byte        `json:"material"`
}

// PendingSignatures reports every node whose current key is unsigned.
//
// Includes the exact bytes to sign rather than expecting the signing tool to
// reconstruct them. Two implementations of "what does the signature cover"
// that drift apart would produce signatures that verify nowhere, and the
// failure would look like a key problem rather than an encoding one.
func (s *Store) PendingSignatures() []UnsignedNode {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []UnsignedNode
	for _, n := range s.state.Nodes {
		if s.signedLocked(n) {
			continue
		}
		out = append(out, UnsignedNode{
			ID:       n.ID,
			Name:     n.Name,
			NodeKey:  n.NodeKey,
			Material: signingMaterial(n.ID, n.NodeKey),
		})
	}
	return out
}

// ApplySignature records a signature for a node, rejecting one that does not
// verify.
//
// Verification happens here even though the server is not the party the
// signature protects against. A signature that does not verify is a mistake
// somebody wants to hear about now, rather than a node that silently drops off
// the mesh the moment the lock is enabled.
func (s *Store) ApplySignature(id netmap.NodeID, sig []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Lock == nil || len(s.state.Lock.TrustedKeys) == 0 {
		return ErrLockDisabled
	}

	var target *Node
	for _, n := range s.state.Nodes {
		if n.ID == id {
			target = n
			break
		}
	}
	if target == nil {
		return fmt.Errorf("no node with id %d", id)
	}

	msg := signingMaterial(target.ID, target.NodeKey)
	ok := false
	for _, k := range s.state.Lock.TrustedKeys {
		if len(k.Public) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(k.Public), msg, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("signature for node %d does not verify against any trusted key", id)
	}

	target.KeySignature = sig
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}
