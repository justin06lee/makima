package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
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
// This is why the node and machine keys were separated from the very first
// commit rather than retrofitted: signing the WireGuard key specifically is
// what makes the guarantee meaningful, and it only works if that key was never
// the same thing as the node's identity to the server.

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
	}
	for _, n := range s.state.Nodes {
		if len(n.KeySignature) > 0 {
			st.Signed++
		} else {
			st.Unsigned++
		}
	}
	return st
}

// AddSigningKey trusts a new authority.
func (s *Store) AddSigningKey(name string, pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("signing key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Lock == nil {
		s.state.Lock = &Lock{Created: time.Now().UTC()}
	}
	if s.state.Lock.Trusts(pub) {
		return fmt.Errorf("that signing key is already trusted")
	}

	s.state.Lock.TrustedKeys = append(s.state.Lock.TrustedKeys, SigningKey{
		Public: pub,
		Name:   name,
		Added:  time.Now().UTC(),
	})
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// RemoveSigningKey stops trusting an authority.
//
// Refuses to remove the last one while the lock is enabled: doing so would
// leave a mesh that enforces signatures with nothing able to produce a valid
// one, and every node would reject every peer on its next netmap.
func (s *Store) RemoveSigningKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Lock == nil {
		return ErrLockDisabled
	}

	kept := make([]SigningKey, 0, len(s.state.Lock.TrustedKeys))
	found := false
	for _, k := range s.state.Lock.TrustedKeys {
		if k.ID() == id {
			found = true
			continue
		}
		kept = append(kept, k)
	}
	if !found {
		return fmt.Errorf("no trusted signing key with id %q", id)
	}
	if len(kept) == 0 && s.state.Lock.Enabled {
		return fmt.Errorf("that is the only trusted key and the lock is enabled; disable the lock first, or the mesh would reject every node")
	}

	s.state.Lock.TrustedKeys = kept
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// SetLockEnabled turns enforcement on or off.
//
// Turning it on is refused while any node is unsigned. The alternative —
// enabling and letting the unsigned nodes drop out — is a self-inflicted
// partition that is hard to diagnose from inside, because the nodes that could
// tell you what happened are the ones that just became unreachable.
func (s *Store) SetLockEnabled(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Lock == nil {
		return fmt.Errorf("no signing key is trusted yet; add one with 'makima-server lock add-key'")
	}
	if on {
		if len(s.state.Lock.TrustedKeys) == 0 {
			return fmt.Errorf("no signing key is trusted yet; add one with 'makima-server lock add-key'")
		}
		var unsigned []string
		for _, n := range s.state.Nodes {
			if len(n.KeySignature) == 0 {
				unsigned = append(unsigned, n.Name)
			}
		}
		if len(unsigned) > 0 {
			return fmt.Errorf("these nodes have no key signature and would be rejected by the whole mesh: %v\nsign them first with 'makima-server lock sign'", unsigned)
		}
	}

	s.state.Lock.Enabled = on
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
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
		if len(n.KeySignature) > 0 {
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
