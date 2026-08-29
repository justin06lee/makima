package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/justin06lee/makima/internal/key"
)

func signingPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// registerNode joins a node and returns its record.
func registerNode(t *testing.T, s *Store, name string) *Node {
	t.Helper()

	auth, err := s.MintAuthKey(true, 0)
	if err != nil {
		t.Fatal(err)
	}
	machineKey, _ := key.NewPrivate()
	nodeKey, _ := key.NewPrivate()
	discoKey, _ := key.NewPrivate()

	n, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: name, NodeKey: nodeKey.Public(), DiscoKey: discoKey.Public(), AuthKey: auth.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A mesh with no lock behaves exactly as it always did.
func TestDisabledLockAdmitsEveryone(t *testing.T) {
	var l *Lock
	if err := l.VerifyNodeKey(1, key.Public{1}, nil); err != nil {
		t.Errorf("a nil lock rejected a node: %v", err)
	}

	l = &Lock{Enabled: false}
	if err := l.VerifyNodeKey(1, key.Public{1}, nil); err != nil {
		t.Errorf("a disabled lock rejected a node: %v", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv := signingPair(t)
	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}

	nodeKey, _ := key.NewPrivate()
	sig := SignNodeKey(priv, 7, nodeKey.Public())

	if err := l.VerifyNodeKey(7, nodeKey.Public(), sig); err != nil {
		t.Errorf("a valid signature did not verify: %v", err)
	}
}

// The signature binds the key to the node ID. Without that binding a
// compromised server could move a legitimately signed key onto a different
// node record and reassign its address.
func TestSignatureIsBoundToTheNodeID(t *testing.T) {
	pub, priv := signingPair(t)
	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}

	nodeKey, _ := key.NewPrivate()
	sig := SignNodeKey(priv, 7, nodeKey.Public())

	if err := l.VerifyNodeKey(8, nodeKey.Public(), sig); err == nil {
		t.Error("a signature for node 7 verified for node 8")
	}
}

func TestSignatureIsBoundToTheKey(t *testing.T) {
	pub, priv := signingPair(t)
	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}

	a, _ := key.NewPrivate()
	b, _ := key.NewPrivate()
	sig := SignNodeKey(priv, 7, a.Public())

	if err := l.VerifyNodeKey(7, b.Public(), sig); err == nil {
		t.Error("a signature over one node key verified another")
	}
}

// The whole point: a server that invents a peer has to forge a signature it
// holds no key for.
func TestUntrustedSignerRejected(t *testing.T) {
	trusted, _ := signingPair(t)
	_, attackerPriv := signingPair(t)

	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: trusted}}}

	nodeKey, _ := key.NewPrivate()
	sig := SignNodeKey(attackerPriv, 7, nodeKey.Public())

	if err := l.VerifyNodeKey(7, nodeKey.Public(), sig); err == nil {
		t.Error("a signature from an untrusted key was accepted")
	}
}

func TestMissingSignatureRejectedWhenEnabled(t *testing.T) {
	pub, _ := signingPair(t)
	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}

	nodeKey, _ := key.NewPrivate()
	if err := l.VerifyNodeKey(7, nodeKey.Public(), nil); err == nil {
		t.Error("an unsigned node was admitted while the lock was enabled")
	}
}

// Rotation without a flag day: both keys are trusted at once.
func TestMultipleTrustedKeys(t *testing.T) {
	oldPub, oldPriv := signingPair(t)
	newPub, newPriv := signingPair(t)

	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: oldPub}, {Public: newPub}}}

	nodeKey, _ := key.NewPrivate()
	for name, priv := range map[string]ed25519.PrivateKey{"old": oldPriv, "new": newPriv} {
		sig := SignNodeKey(priv, 7, nodeKey.Public())
		if err := l.VerifyNodeKey(7, nodeKey.Public(), sig); err != nil {
			t.Errorf("a signature from the %s key did not verify: %v", name, err)
		}
	}
}

// --- store integration ---------------------------------------------------

func TestEnableRefusedWhileNodesAreUnsigned(t *testing.T) {
	s := newStore(t)
	registerNode(t, s, "laptop")

	pub, _ := signingPair(t)
	if err := s.AddSigningKey("admin", pub); err != nil {
		t.Fatal(err)
	}

	// Enabling here would partition the mesh: every node would reject the
	// unsigned one, including the one you are sitting at.
	if err := s.SetLockEnabled(true); err == nil {
		t.Error("the lock was enabled while a node had no signature")
	}
}

func TestSignThenEnable(t *testing.T) {
	s := newStore(t)
	registerNode(t, s, "laptop")

	pub, priv := signingPair(t)
	if err := s.AddSigningKey("admin", pub); err != nil {
		t.Fatal(err)
	}

	pending := s.PendingSignatures()
	if len(pending) != 1 {
		t.Fatalf("%d nodes pending, want 1", len(pending))
	}

	sig := ed25519.Sign(priv, pending[0].Material)
	if err := s.ApplySignature(pending[0].ID, sig); err != nil {
		t.Fatal(err)
	}

	if err := s.SetLockEnabled(true); err != nil {
		t.Fatalf("could not enable the lock with every node signed: %v", err)
	}

	st := s.LockStatus()
	if !st.Enabled || st.Signed != 1 || st.Unsigned != 0 {
		t.Errorf("status is %+v, want enabled with one signed node", st)
	}
}

// The server verifies before storing, so a mistake is an error message rather
// than a node that silently drops off when the lock is enabled.
func TestBadSignatureRefusedByStore(t *testing.T) {
	s := newStore(t)
	n := registerNode(t, s, "laptop")

	pub, _ := signingPair(t)
	if err := s.AddSigningKey("admin", pub); err != nil {
		t.Fatal(err)
	}

	if err := s.ApplySignature(n.ID, []byte("not a signature")); err == nil {
		t.Error("a garbage signature was stored")
	}
}

// Removing the only trusted key while enforcing would leave a mesh that
// verifies signatures nothing can produce.
func TestCannotRemoveLastKeyWhileEnabled(t *testing.T) {
	s := newStore(t)

	pub, priv := signingPair(t)
	if err := s.AddSigningKey("admin", pub); err != nil {
		t.Fatal(err)
	}
	n := registerNode(t, s, "laptop")
	sig := SignNodeKey(priv, n.ID, n.NodeKey)
	if err := s.ApplySignature(n.ID, sig); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLockEnabled(true); err != nil {
		t.Fatal(err)
	}

	id := s.LockStatus().TrustedKeys[0].ID()
	if err := s.RemoveSigningKey(id); err == nil {
		t.Error("the only trusted key was removed while the lock was enforcing")
	}
}

// A rotated node key invalidates its signature, which must be dropped rather
// than left to fail verification mesh-wide.
func TestKeyRotationClearsTheSignature(t *testing.T) {
	s := newStore(t)

	pub, priv := signingPair(t)
	if err := s.AddSigningKey("admin", pub); err != nil {
		t.Fatal(err)
	}

	auth, _ := s.MintAuthKey(true, 0)
	machineKey, _ := key.NewPrivate()
	nodeKey, _ := key.NewPrivate()
	discoKey, _ := key.NewPrivate()

	n, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: "laptop", NodeKey: nodeKey.Public(), DiscoKey: discoKey.Public(), AuthKey: auth.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, n.ID, n.NodeKey)); err != nil {
		t.Fatal(err)
	}

	rotated, _ := key.NewPrivate()
	after, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: "laptop", NodeKey: rotated.Public(), DiscoKey: discoKey.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(after.KeySignature) != 0 {
		t.Error("the old signature survived a key rotation; it covers a key that no longer exists")
	}
	if after.KeyRotatedAt.IsZero() {
		t.Error("the rotation was not recorded")
	}
}

// The trusted keys travel to nodes in the netmap, because a node that had to
// ask the server what to trust would be trusting the server again.
func TestNetMapCarriesTheLock(t *testing.T) {
	s := newStore(t)

	pub, priv := signingPair(t)
	if err := s.AddSigningKey("admin", pub); err != nil {
		t.Fatal(err)
	}

	auth, _ := s.MintAuthKey(true, 0)
	machineKey, _ := key.NewPrivate()
	nodeKey, _ := key.NewPrivate()
	discoKey, _ := key.NewPrivate()
	n, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: "laptop", NodeKey: nodeKey.Public(), DiscoKey: discoKey.Public(), AuthKey: auth.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, n.ID, n.NodeKey)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLockEnabled(true); err != nil {
		t.Fatal(err)
	}

	resp, err := s.NetMapFor(machineKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Lock == nil || !resp.Lock.Enabled {
		t.Fatal("the netmap does not carry an enabled lock")
	}
	if len(resp.Lock.TrustedKeys) != 1 {
		t.Errorf("%d trusted keys in the netmap, want 1", len(resp.Lock.TrustedKeys))
	}
}

// A peer's signature has to reach the node that verifies it.
func TestNetMapCarriesPeerSignatures(t *testing.T) {
	s := newStore(t)

	pub, priv := signingPair(t)
	if err := s.AddSigningKey("admin", pub); err != nil {
		t.Fatal(err)
	}

	auth, _ := s.MintAuthKey(true, 0)

	selfMachine, _ := key.NewPrivate()
	selfNode, _ := key.NewPrivate()
	if _, err := s.Register(selfMachine.Public(), &RegisterRequest{
		Name: "laptop", NodeKey: selfNode.Public(), AuthKey: auth.Secret,
	}); err != nil {
		t.Fatal(err)
	}

	peerMachine, _ := key.NewPrivate()
	peerNode, _ := key.NewPrivate()
	peer, err := s.Register(peerMachine.Public(), &RegisterRequest{
		Name: "desktop", NodeKey: peerNode.Public(), AuthKey: auth.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}

	sig := SignNodeKey(priv, peer.ID, peer.NodeKey)
	if err := s.ApplySignature(peer.ID, sig); err != nil {
		t.Fatal(err)
	}

	resp, err := s.NetMapFor(selfMachine.Public())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Peers) != 1 {
		t.Fatalf("%d peers, want 1", len(resp.Peers))
	}
	if len(resp.Peers[0].KeySignature) == 0 {
		t.Fatal("the peer's signature did not reach the netmap")
	}

	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}
	if err := l.VerifyNodeKey(resp.Peers[0].ID, resp.Peers[0].Key, resp.Peers[0].KeySignature); err != nil {
		t.Errorf("the signature that reached the node did not verify: %v", err)
	}
}
