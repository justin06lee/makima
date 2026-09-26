package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

// testNetwork stands in for a control plane's key where no store is involved.
var testNetwork = key.Public{0x42}

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
	if err := s.ApplyLockStatement(SignLockStatement(priv, s.ServerKey().Public(), 1, false, [][]byte{pub}), nil); err != nil {
		t.Fatal(err)
	}
}

// changeLock applies the lock's next version, signed with priv.
func changeLock(s *Store, priv ed25519.PrivateKey, enabled bool, keys ...ed25519.PublicKey) error {
	var ks [][]byte
	for _, k := range keys {
		ks = append(ks, k)
	}
	return s.ApplyLockStatement(SignLockStatement(priv, s.ServerKey().Public(), s.LockStatus().Epoch+1, enabled, ks), nil)
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
	if err := l.VerifyNodeKey(testNetwork, 1, key.Public{1}, nil); err != nil {
		t.Errorf("a nil lock rejected a node: %v", err)
	}

	l = &Lock{Enabled: false}
	if err := l.VerifyNodeKey(testNetwork, 1, key.Public{1}, nil); err != nil {
		t.Errorf("a disabled lock rejected a node: %v", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv := signingPair(t)
	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}

	nodeKey, _ := key.NewPrivate()
	sig := SignNodeKey(priv, testNetwork, 7, nodeKey.Public())

	if err := l.VerifyNodeKey(testNetwork, 7, nodeKey.Public(), sig); err != nil {
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
	sig := SignNodeKey(priv, testNetwork, 7, nodeKey.Public())

	if err := l.VerifyNodeKey(testNetwork, 8, nodeKey.Public(), sig); err == nil {
		t.Error("a signature for node 7 verified for node 8")
	}
}

func TestSignatureIsBoundToTheKey(t *testing.T) {
	pub, priv := signingPair(t)
	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}

	a, _ := key.NewPrivate()
	b, _ := key.NewPrivate()
	sig := SignNodeKey(priv, testNetwork, 7, a.Public())

	if err := l.VerifyNodeKey(testNetwork, 7, b.Public(), sig); err == nil {
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
	sig := SignNodeKey(attackerPriv, testNetwork, 7, nodeKey.Public())

	if err := l.VerifyNodeKey(testNetwork, 7, nodeKey.Public(), sig); err == nil {
		t.Error("a signature from an untrusted key was accepted")
	}
}

func TestMissingSignatureRejectedWhenEnabled(t *testing.T) {
	pub, _ := signingPair(t)
	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}

	nodeKey, _ := key.NewPrivate()
	if err := l.VerifyNodeKey(testNetwork, 7, nodeKey.Public(), nil); err == nil {
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
		sig := SignNodeKey(priv, testNetwork, 7, nodeKey.Public())
		if err := l.VerifyNodeKey(testNetwork, 7, nodeKey.Public(), sig); err != nil {
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

	// Both kinds, as lock sign signs them.
	sig := ed25519.Sign(priv, pending[0].Material)
	legacy := ed25519.Sign(priv, pending[0].LegacyMaterial)
	if err := s.ApplySignatures(pending[0].ID, sig, legacy); err != nil {
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
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, s.ServerKey().Public(), n.ID, n.NodeKey)); err != nil {
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
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, s.ServerKey().Public(), n.ID, n.NodeKey)); err != nil {
		t.Fatal(err)
	}
	// And the old kind, as a network locked under makima v0.3.0 carries it.
	s.mu.Lock()
	s.state.Nodes[0].KeySignature = ed25519.Sign(priv, legacySigningMaterial(n.ID, n.NodeKey))
	s.mu.Unlock()

	rotated, _ := key.NewPrivate()
	after, err := s.Register(machineKey.Public(), &RegisterRequest{
		Name: "laptop", NodeKey: rotated.Public(), DiscoKey: discoKey.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(after.KeySignature) != 0 || len(after.NetworkSignature) != 0 {
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
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, s.ServerKey().Public(), n.ID, n.NodeKey)); err != nil {
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
	pin, err := AdvanceLock(s.ServerKey().Public(), nil, resp.Lock.Chain)
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

	sig := SignNodeKey(priv, s.ServerKey().Public(), peer.ID, peer.NodeKey)
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
	if len(resp.Peers[0].NetworkSignature) == 0 {
		t.Fatal("the peer's signature did not reach the netmap")
	}

	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}
	if err := l.VerifyNodeKey(s.ServerKey().Public(), resp.Peers[0].ID, resp.Peers[0].Key, resp.Peers[0].NetworkSignature); err != nil {
		t.Errorf("the signature that reached the node did not verify: %v", err)
	}
}

// pinAt is a node that has accepted the lock up to the store's current
// version, the way it would from its netmaps.
func pinAt(t *testing.T, s *Store) *netmap.LockPin {
	t.Helper()
	pin, err := AdvanceLock(s.ServerKey().Public(), nil, s.LockChain())
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
	forged := append(s.LockChain(), SignLockStatement(rogue, s.ServerKey().Public(), 3, false, [][]byte{pub}))

	after, err := AdvanceLock(s.ServerKey().Public(), pin, forged)
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
	forged := append(s.LockChain(), SignLockStatement(rogue, s.ServerKey().Public(), 2, true, [][]byte{pub, roguePub}))
	if after, err := AdvanceLock(s.ServerKey().Public(), pin, forged); err == nil || containsKey(after.Keys, roguePub) {
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
		SignLockStatement(rogue, s.ServerKey().Public(), 1, false, [][]byte{roguePub}),
		SignLockStatement(rogue, s.ServerKey().Public(), 2, false, [][]byte{roguePub}),
		SignLockStatement(rogue, s.ServerKey().Public(), 3, false, [][]byte{roguePub}),
	}
	after, err := AdvanceLock(s.ServerKey().Public(), pin, history)
	if err == nil || !after.Enabled || containsKey(after.Keys, roguePub) {
		t.Errorf("a rewritten history moved the pin to %+v (%v)", after, err)
	}
}

// One signing key can serve two networks. A version made for one must not
// move the other's lock: it used to, because a version named no network, so
// network B's server could show its nodes network A's "version 3: not
// enforced" and switch B's lock off.
func TestAVersionSignedForAnotherNetworkIsRefused(t *testing.T) {
	pub, priv := signingPair(t)

	b := newStore(t)
	startLock(t, b, pub, priv)
	if err := changeLock(b, priv, true, pub); err != nil {
		t.Fatal(err)
	}
	pin := pinAt(t, b)

	a := newStore(t)
	startLock(t, a, pub, priv)
	if err := changeLock(a, priv, true, pub); err != nil {
		t.Fatal(err)
	}
	if err := changeLock(a, priv, false, pub); err != nil {
		t.Fatal(err)
	}

	after, err := AdvanceLock(b.ServerKey().Public(), pin, a.LockChain())
	if err == nil || after.Epoch != 2 || !after.Enabled {
		t.Errorf("network A's versions moved network B's lock to %+v (%v)", after, err)
	}

	// Nor does B's server take it, so an operator pointing the wrong key file
	// at the wrong server hears about it rather than every node ignoring it.
	if err := b.ApplyLockStatement(a.LockChain()[2], nil); err == nil {
		t.Error("network B's server took a version signed for network A")
	}
}

// A node that somehow has no control plane key cannot tell its network's lock
// from another's, so it takes none rather than any.
func TestALockIsNotFollowedWithoutTheNetworksKey(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)

	if pin, err := AdvanceLock(key.Public{}, nil, s.LockChain()); err == nil || pin != nil {
		t.Errorf("with no network key the chain pinned %+v (%v)", pin, err)
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

	after, err := AdvanceLock(s.ServerKey().Public(), pin, s.LockChain())
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

	skip := []LockStatement{SignLockStatement(priv, s.ServerKey().Public(), 3, true, [][]byte{pub})}
	if after, err := AdvanceLock(s.ServerKey().Public(), pin, skip); err == nil || after.Epoch != 1 {
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
	if err := s.ApplyLockStatement(SignLockStatement(priv, s.ServerKey().Public(), 1, false, [][]byte{pub}), nil); err == nil {
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
	if err := s.ApplyLockStatement(SignLockStatement(rogue, s.ServerKey().Public(), 1, false, [][]byte{roguePub}), nil); err == nil {
		t.Error("an untrusted key sealed an older lock with itself")
	}
	if err := s.ApplyLockStatement(SignLockStatement(priv, s.ServerKey().Public(), 1, false, [][]byte{pub}), nil); err != nil {
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
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, s.ServerKey().Public(), n.ID, n.NodeKey)); err != nil {
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
	empty := SignLockStatement(priv, s.ServerKey().Public(), 2, false, nil)
	if after, err := AdvanceLock(s.ServerKey().Public(), pinAt(t, s), []LockStatement{empty}); err == nil || after.Epoch != 1 {
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
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, s.ServerKey().Public(), n.ID, n.NodeKey)); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetLock(); err != nil {
		t.Fatal(err)
	}
	if len(s.Nodes()[0].NetworkSignature) == 0 {
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

// One signing key trusted by two networks: a machine signed into one must not
// pass in the other. It did — a node's signature covered its ID and key and
// nothing else — so network B's server could show its nodes a machine the
// operator only ever signed into network A, and have it admitted.
func TestANodeSignedIntoAnotherNetworkIsRefused(t *testing.T) {
	pub, priv := signingPair(t)

	a := newStore(t)
	startLock(t, a, pub, priv)
	x := registerNode(t, a, "x")
	if err := a.ApplySignature(x.ID, SignNodeKey(priv, a.ServerKey().Public(), x.ID, x.NodeKey)); err != nil {
		t.Fatal(err)
	}
	xs := a.Nodes()[0]

	b := newStore(t)
	startLock(t, b, pub, priv)
	if err := changeLock(b, priv, true, pub); err != nil {
		t.Fatal(err)
	}
	pin := pinAt(t, b)

	if err := VerifyPinned(b.ServerKey().Public(), pin, xs.ID, xs.NodeKey, xs.NetworkSignature); err == nil {
		t.Errorf("network B's node admits %q, signed only into network A", xs.Name)
	}

	// Nor does B's server record such a signature for a node of its own.
	y := registerNode(t, b, "y")
	if err := b.ApplySignature(y.ID, SignNodeKey(priv, a.ServerKey().Public(), y.ID, y.NodeKey)); err == nil {
		t.Error("network B's server took a signature made for network A")
	}
}

// legacyLockedStore is a network as makima v0.3.0 left it: a lock trusting
// pub, never signed as versions, and every node signed the old way — over its
// ID and key, naming no network.
func legacyLockedStore(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, enabled bool, names ...string) *Store {
	t.Helper()
	s := newStore(t)
	for _, name := range names {
		registerNode(t, s, name)
	}
	s.mu.Lock()
	s.state.Lock = &Lock{TrustedKeys: []SigningKey{{Public: pub}}, Enabled: enabled}
	for _, n := range s.state.Nodes {
		n.KeySignature = ed25519.Sign(priv, legacySigningMaterial(n.ID, n.NodeKey))
	}
	s.mu.Unlock()
	return s
}

// A network locked under makima v0.3.0 has only old signatures. A node that
// held a signed lock would refuse every one of them, so the server refuses to
// seal an enforced lock until each node is signed for this network — and
// lists them as waiting, with the material that names it.
func TestAnOldNetworkIsReSignedBeforeItsLockIsSealed(t *testing.T) {
	pub, priv := signingPair(t)
	s := legacyLockedStore(t, pub, priv, true, "laptop", "desktop")

	if st := s.LockStatus(); st.Signed != 0 || st.Unsigned != 2 {
		t.Errorf("status %+v: old signatures counted as signed for this network", st)
	}
	pending := s.PendingSignatures()
	if len(pending) != 2 {
		t.Fatalf("%d nodes waiting, want 2", len(pending))
	}

	seal := SignLockStatement(priv, s.ServerKey().Public(), 1, true, [][]byte{pub})
	if err := s.ApplyLockStatement(seal, nil); err == nil {
		t.Fatal("an enforced lock was sealed while every node had only an old signature")
	}

	for _, n := range pending {
		if err := s.ApplySignature(n.ID, ed25519.Sign(priv, n.Material)); err != nil {
			t.Fatalf("sign %s: %v", n.Name, err)
		}
	}
	if err := s.ApplyLockStatement(seal, nil); err != nil {
		t.Fatalf("sealing after re-signing: %v", err)
	}

	// And the node that pins it admits the re-signed peers.
	pin := pinAt(t, s)
	for _, n := range s.Nodes() {
		if err := VerifyPinned(s.ServerKey().Public(), pin, n.ID, n.NodeKey, n.NetworkSignature); err != nil {
			t.Errorf("%s after re-signing: %v", n.Name, err)
		}
		if len(n.KeySignature) == 0 {
			t.Errorf("%s lost its old signature, which machines still on v0.3.0 check", n.Name)
		}
	}
}

// The old kind is still honoured where no signed lock is held: that lock is
// the server's word anyway, and a v0.3.0 network must keep working between
// upgrading and re-signing.
func TestAnOldSignatureStillCountsUnderAnUnsignedLock(t *testing.T) {
	pub, priv := signingPair(t)
	l := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}
	nodeKey, _ := key.NewPrivate()
	old := ed25519.Sign(priv, legacySigningMaterial(7, nodeKey.Public()))

	if err := l.VerifyLegacy(testNetwork, 7, nodeKey.Public(), nil, old); err != nil {
		t.Errorf("an old signature was refused under an unsigned lock: %v", err)
	}
	if err := l.VerifyNodeKey(testNetwork, 7, nodeKey.Public(), old); err == nil {
		t.Error("an old signature, naming no network, passed as one that does")
	}
}

// The old kind is what makima v0.3.0 made and still checks: its bytes must
// not move, or every signature a v0.3.0 network holds stops verifying.
func TestTheOldSignatureMaterialIsUnchanged(t *testing.T) {
	var k key.Public
	for i := range k {
		k[i] = byte(i)
	}
	got := legacySigningMaterial(0x0102030405060708, k)
	want := append([]byte{1, 1, 2, 3, 4, 5, 6, 7, 8}, k[:]...)
	if !bytes.Equal(got, want) {
		t.Errorf("legacy material %x, want %x", got, want)
	}
}

// An expired machine may have been stolen. It is not listed for signing — a
// signed key outlives the expiry and would be admitted again the moment it
// re-registered — nor counted, nor waited for before the lock is enforced,
// and a signature for it is refused.
func TestAnExpiredMachineIsNeitherSignedNorWaitedFor(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	laptop := registerNode(t, s, "laptop")
	stolen := registerNode(t, s, "stolen")
	if err := s.ApplySignatures(laptop.ID,
		SignNodeKey(priv, s.ServerKey().Public(), laptop.ID, laptop.NodeKey),
		ed25519.Sign(priv, legacySigningMaterial(laptop.ID, laptop.NodeKey))); err != nil {
		t.Fatal(err)
	}
	if err := s.ExpireNode("stolen"); err != nil {
		t.Fatal(err)
	}

	for _, n := range s.PendingSignatures() {
		if n.Name == "stolen" {
			t.Error("the expired machine is listed for signing")
		}
	}
	if st := s.LockStatus(); st.Signed != 1 || st.Unsigned != 0 {
		t.Errorf("status %+v: the expired machine was counted", st)
	}
	if err := s.ApplySignature(stolen.ID, SignNodeKey(priv, s.ServerKey().Public(), stolen.ID, stolen.NodeKey)); err == nil {
		t.Error("a signature for the expired machine was recorded")
	}
	if err := changeLock(s, priv, true, pub); err != nil {
		t.Errorf("enforcing was refused over the expired machine: %v", err)
	}
}

// Expiring takes both kinds of signature away, or re-admitting the machine
// would silently restore whichever was left.
func TestExpiringDropsBothSignatures(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	n := registerNode(t, s, "laptop")
	if err := s.ApplySignature(n.ID, SignNodeKey(priv, s.ServerKey().Public(), n.ID, n.NodeKey)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.state.Nodes[0].KeySignature = ed25519.Sign(priv, legacySigningMaterial(n.ID, n.NodeKey))
	s.mu.Unlock()

	if err := s.ExpireNode("laptop"); err != nil {
		t.Fatal(err)
	}
	if after := s.Nodes()[0]; len(after.KeySignature) != 0 || len(after.NetworkSignature) != 0 {
		t.Error("a signature survived the expiry")
	}
}

// Machines still on makima v0.3.0 check only the old kind of signature. A
// machine signed after the upgrade used to get only the new kind, so every one
// of them refused it — and enabling the lock on the new server had them refuse
// every peer. Both kinds are asked for now, and a machine missing either is
// still waiting.
func TestAMachineIsSignedForOldMachinesToo(t *testing.T) {
	s := newStore(t)
	pub, priv := signingPair(t)
	startLock(t, s, pub, priv)
	n := registerNode(t, s, "laptop")

	pending := s.PendingSignatures()
	if len(pending) != 1 || len(pending[0].LegacyMaterial) == 0 {
		t.Fatalf("pending %+v: no old-kind material asked for", pending)
	}

	// Only the new kind: still waiting on the old one.
	if err := s.ApplySignature(n.ID, ed25519.Sign(priv, pending[0].Material)); err != nil {
		t.Fatal(err)
	}
	if len(s.PendingSignatures()) != 1 {
		t.Error("a machine with no old-kind signature is not waiting for one")
	}
	// And status agrees, or it says "every node is signed, enable" while
	// lock sign still has a machine to sign.
	if st := s.LockStatus(); st.Signed != 0 || st.Unsigned != 1 {
		t.Errorf("status %+v with only the new kind signed, want it counted as unsigned", st)
	}

	// Both, and a wrong old kind is refused.
	if err := s.ApplySignatures(n.ID, ed25519.Sign(priv, pending[0].Material), ed25519.Sign(priv, []byte("something else"))); err == nil {
		t.Error("an old-kind signature over the wrong bytes was recorded")
	}
	if err := s.ApplySignatures(n.ID, ed25519.Sign(priv, pending[0].Material), ed25519.Sign(priv, pending[0].LegacyMaterial)); err != nil {
		t.Fatal(err)
	}
	if len(s.PendingSignatures()) != 0 {
		t.Error("a machine with both kinds is still waiting")
	}

	// What a v0.3.0 machine checks: the old kind, over ID and key.
	got := s.Nodes()[0]
	old := &Lock{Enabled: true, TrustedKeys: []SigningKey{{Public: pub}}}
	if err := old.VerifyLegacy(key.Public{}, got.ID, got.NodeKey, nil, got.KeySignature); err != nil {
		t.Errorf("a v0.3.0 machine would refuse it: %v", err)
	}
}
