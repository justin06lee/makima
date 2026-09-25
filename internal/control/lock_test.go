package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

func signingPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// startLock sets up a lock trusting pub alone, not enforced: version 1.
func startLock(t *testing.T, s *Store, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	if err := s.ApplyLockStatement(SignLockStatement(priv, 1, false, [][]byte{pub}), nil); err != nil {
		t.Fatal(err)
	}
}

// changeLock applies the lock's next version, signed with priv.
func changeLock(s *Store, priv ed25519.PrivateKey, enabled bool, keys ...ed25519.PublicKey) error {
	var ks [][]byte
	for _, k := range keys {
		ks = append(ks, k)
	}
	return s.ApplyLockStatement(SignLockStatement(priv, s.LockStatus().Epoch+1, enabled, ks), nil)
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

	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)

	// Enabling here would partition the mesh: every node would reject the
	// unsigned one, including the one you are sitting at.
	if err := changeLock(s, priv, true, pub); err == nil {
		t.Error("the lock was enabled while a node had no signature")
	}
}

func TestSignThenEnable(t *testing.T) {
	s := newStore(t)
	registerNode(t, s, "laptop")

	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)

	pending := s.PendingSignatures()
	if len(pending) != 1 {
		t.Fatalf("%d nodes pending, want 1", len(pending))
	}

	sig := ed25519.Sign(priv, pending[0].Material)
	if err := s.ApplySignature(pending[0].ID, sig); err != nil {
		t.Fatal(err)
	}

	if err := changeLock(s, priv, true, pub); err != nil {
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

	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)

	if err := s.ApplySignature(n.ID, []byte("not a signature")); err == nil {
		t.Error("a garbage signature was stored")
	}
}

// Removing the only trusted key while enforcing would leave a mesh that
// verifies signatures nothing can produce — and so would removing a key the
// nodes' signatures depend on.
func TestCannotEnforceAKeySetTheNodesAreNotSignedBy(t *testing.T) {
	s := newStore(t)

	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	n := registerNode(t, s, "laptop")
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, n.ID, n.NodeKey)); err != nil {
		t.Fatal(err)
	}
	if err := changeLock(s, priv, true, pub); err != nil {
		t.Fatal(err)
	}

	if err := changeLock(s, priv, true); err == nil {
		t.Error("the only trusted key was removed while the lock was enforcing")
	}
	other, _ := signingPair(t)
	if err := changeLock(s, priv, true, other); err == nil {
		t.Error("the key every node is signed by was swapped out while the lock was enforcing")
	}
}

// A rotated node key invalidates its signature, which must be dropped rather
// than left to fail verification mesh-wide.
func TestKeyRotationClearsTheSignature(t *testing.T) {
	s := newStore(t)

	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)

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
	startLock(t, s, pub, priv)

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
	if err := changeLock(s, priv, true, pub); err != nil {
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
	pin, err := AdvanceLock(nil, resp.Lock.Chain)
	if err != nil || pin == nil || !pin.Enabled || pin.Epoch != 2 {
		t.Errorf("the chain in the netmap pins %+v, %v; want version 2, enforced", pin, err)
	}
}

// A peer's signature has to reach the node that verifies it.
func TestNetMapCarriesPeerSignatures(t *testing.T) {
	s := newStore(t)

	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)

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

// pinAt is a node that has accepted the lock up to the store's current
// version, the way it would from its netmaps.
func pinAt(t *testing.T, s *Store) *netmap.LockPin {
	t.Helper()
	pin, err := AdvanceLock(nil, s.LockChain())
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

// The attack the lock exists for, from the server's side: it cannot switch a
// node's lock off by saying so.
func TestServerCannotSwitchThePinnedLockOff(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	if err := changeLock(s, priv, true, pub); err != nil {
		t.Fatal(err)
	}
	pin := pinAt(t, s)

	// The server's own key, or any key that is not trusted, signing
	// "version 3: not enforced".
	_, rogue := signingPair(t)
	forged := append(s.LockChain(), SignLockStatement(rogue, 3, false, [][]byte{pub}))

	after, err := AdvanceLock(pin, forged)
	if err == nil {
		t.Error("a version signed by an untrusted key was accepted")
	}
	if !after.Enabled || after.Epoch != 2 {
		t.Errorf("the pinned lock moved to %+v", after)
	}
}

func TestServerCannotTrustAKeyOfItsOwn(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	pin := pinAt(t, s)

	roguePub, rogue := signingPair(t)
	forged := append(s.LockChain(), SignLockStatement(rogue, 2, true, [][]byte{pub, roguePub}))
	if after, err := AdvanceLock(pin, forged); err == nil || containsKey(after.Keys, roguePub) {
		t.Error("a key the lock never trusted signed itself in")
	}
}

// A server that writes a whole new history, starting from its own first
// version, gets nowhere with a node that already holds the real one.
func TestServerCannotRewriteHistory(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	if err := changeLock(s, priv, true, pub); err != nil {
		t.Fatal(err)
	}
	pin := pinAt(t, s)

	roguePub, rogue := signingPair(t)
	history := []LockStatement{
		SignLockStatement(rogue, 1, false, [][]byte{roguePub}),
		SignLockStatement(rogue, 2, false, [][]byte{roguePub}),
		SignLockStatement(rogue, 3, false, [][]byte{roguePub}),
	}
	after, err := AdvanceLock(pin, history)
	if err == nil || !after.Enabled || containsKey(after.Keys, roguePub) {
		t.Errorf("a rewritten history moved the pin to %+v (%v)", after, err)
	}
}

// Rotating the signing key — trust the new one, then drop the old, each step
// signed by a key the step before trusted — is followed by a node that was
// away for all of it.
func TestNodeFollowsARotationItMissed(t *testing.T) {
	s := newStore(t)
	oldPub, oldPriv := signingPair(t)
	startLock(t, s, oldPub, oldPriv)
	pin := pinAt(t, s)

	newPub, newPriv := signingPair(t)
	if err := changeLock(s, oldPriv, false, oldPub, newPub); err != nil {
		t.Fatal(err)
	}
	if err := changeLock(s, newPriv, false, newPub); err != nil {
		t.Fatal(err)
	}

	after, err := AdvanceLock(pin, s.LockChain())
	if err != nil {
		t.Fatal(err)
	}
	if after.Epoch != 3 || len(after.Keys) != 1 || !containsKey(after.Keys, newPub) {
		t.Errorf("the node ended at %+v, want version 3 trusting only the new key", after)
	}
}

func TestMissingVersionsStopTheWalk(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	pin := pinAt(t, s)

	skip := []LockStatement{SignLockStatement(priv, 3, true, [][]byte{pub})}
	if after, err := AdvanceLock(pin, skip); err == nil || after.Epoch != 1 {
		t.Errorf("a version with a gap before it was accepted: %+v", after)
	}
}

func TestStoreRefusesWhatNodesWouldRefuse(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)

	_, rogue := signingPair(t)
	if err := changeLock(s, rogue, false, pub); err == nil {
		t.Error("the store took a version signed by an untrusted key")
	}
	if err := s.ApplyLockStatement(SignLockStatement(priv, 1, false, [][]byte{pub}), nil); err == nil {
		t.Error("the store took a version it already has")
	}
	if got := s.LockStatus().Epoch; got != 1 {
		t.Errorf("the lock is at version %d after two refusals, want 1", got)
	}
}

// A lock set up before versions were signed has nothing a node can pin.
// Sealing it has to come from a key it already trusts.
func TestSealingAnOlderLock(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	s.state.Lock = &Lock{TrustedKeys: []SigningKey{{Public: pub, Name: "admin"}}}

	_, rogue := signingPair(t)
	roguePub := rogue.Public().(ed25519.PublicKey)
	if err := s.ApplyLockStatement(SignLockStatement(rogue, 1, false, [][]byte{roguePub}), nil); err == nil {
		t.Error("an untrusted key sealed an older lock with itself")
	}
	if err := s.ApplyLockStatement(SignLockStatement(priv, 1, false, [][]byte{pub}), nil); err != nil {
		t.Fatalf("the trusted key could not seal the lock: %v", err)
	}
	if st := s.LockStatus(); st.Epoch != 1 || st.TrustedKeys[0].Name != "admin" {
		t.Errorf("after sealing: %+v", st)
	}
}

func TestForgetLockEmptiesTheLock(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	n := registerNode(t, s, "laptop")
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, n.ID, n.NodeKey)); err != nil {
		t.Fatal(err)
	}

	if err := s.ForgetLock(); err != nil {
		t.Fatal(err)
	}
	if st := s.LockStatus(); len(st.TrustedKeys) != 0 || st.Signed != 0 {
		t.Errorf("after forgetting: %+v", st)
	}
}

// A version that trusts no key could never be followed by another: the lock
// would be stuck there on every node that took it.
func TestAVersionTrustingNoKeyIsRefused(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	if err := changeLock(s, priv, false); err == nil {
		t.Error("the store took a version that trusts no key")
	}
	empty := SignLockStatement(priv, 2, false, nil)
	if after, err := AdvanceLock(pinAt(t, s), []LockStatement{empty}); err == nil || after.Epoch != 1 {
		t.Error("a node took a version that trusts no key")
	}
}

// Forgetting the lock keeps the nodes' signatures: machines still holding
// the lock check their peers against them, and wiping them had every such
// machine refuse every peer — the ones you would reach to reset it included.
func TestForgettingTheLockKeepsSignaturesButNotTheirStanding(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	n := registerNode(t, s, "laptop")
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, n.ID, n.NodeKey)); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetLock(); err != nil {
		t.Fatal(err)
	}
	if len(s.Nodes()[0].KeySignature) == 0 {
		t.Error("the signature was wiped")
	}

	// A new lock with a new key does not count the old signature.
	pub2, priv2 := signingPair(t)
	startLock(t, s, pub2, priv2)
	if st := s.LockStatus(); st.Signed != 0 || st.Unsigned != 1 {
		t.Errorf("status %+v: an old key's signature counted under the new lock", st)
	}
	if len(s.PendingSignatures()) != 1 {
		t.Error("the node signed by the forgotten key is not waiting to be signed again")
	}
}
