package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

// signedPeer is a peer signed into the network whose control plane holds
// net, or unsigned when signer is nil.
func signedPeer(t *testing.T, net key.Public, id netmap.NodeID, name string, signer ed25519.PrivateKey) netmap.Node {
	t.Helper()
	k, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	p := netmap.Node{ID: id, Name: name, Key: k.Public()}
	if signer != nil {
		p.NetworkSignature = control.SignNodeKey(signer, net, id, p.Key)
	}
	return p
}

// network is a control plane's key: the network a lock's versions are for.
func network(t *testing.T) key.Public {
	t.Helper()
	k, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	return k.Public()
}

// The control plane turning against the network: it drops the lock from the
// netmap, or sends it switched off without a signed version saying so, and
// introduces a peer of its own. A node holding the lock refuses the peer
// either way. Before, the node took the lock's state from each netmap, so
// either move admitted anyone.
func TestPinnedLockOutlivesTheServerSayingOtherwise(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ours := network(t)
	pin := &netmap.LockPin{Epoch: 2, Enabled: true, Keys: [][]byte{pub}}

	real := signedPeer(t, ours, 1, "laptop", priv)
	invented := signedPeer(t, ours, 2, "intruder", nil)

	for name, lock := range map[string]*control.LockConfig{
		"no lock":        nil,
		"switched off":   {Enabled: false},
		"rogue key only": {Enabled: true, TrustedKeys: []control.SigningKey{{Public: make([]byte, 32)}}},
	} {
		resp := &control.MapResponse{Peers: []netmap.Node{real, invented}, Lock: lock}
		kept, rejected, after, _ := verifyPeers(resp, ours, pin)
		if len(kept) != 1 || kept[0].Name != "laptop" || len(rejected) != 1 {
			t.Errorf("%s: kept %v", name, kept)
		}
		if after != pin {
			t.Errorf("%s: the pin moved to %+v", name, after)
		}
	}
}

// A node that has never seen a lock takes the network's first signed
// version, and from then on holds it.
func TestFirstLockIsPinned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ours := network(t)
	chain := []control.LockStatement{
		control.SignLockStatement(priv, ours, 1, false, [][]byte{pub}),
		control.SignLockStatement(priv, ours, 2, true, [][]byte{pub}),
	}
	resp := &control.MapResponse{
		Peers: []netmap.Node{signedPeer(t, ours, 1, "laptop", priv), signedPeer(t, ours, 2, "intruder", nil)},
		Lock:  &control.LockConfig{Enabled: true, Chain: chain},
	}
	kept, _, pin, err := verifyPeers(resp, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pin == nil || pin.Epoch != 2 || !pin.Enabled {
		t.Fatalf("pinned %+v", pin)
	}
	if len(kept) != 1 {
		t.Errorf("kept %d peers, want only the signed one", len(kept))
	}
}

// A node holding its network's lock is not moved by a version the same
// signing key made for another network. It used to be: the version named no
// network, so another network's "not enforced" switched this one's lock off,
// and the peer its server invented was admitted.
func TestAnotherNetworksLockDoesNotMoveThePin(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ours, theirs := network(t), network(t)
	pin := &netmap.LockPin{Epoch: 2, Enabled: true, Keys: [][]byte{pub}}

	replayed := []control.LockStatement{
		control.SignLockStatement(priv, theirs, 1, false, [][]byte{pub}),
		control.SignLockStatement(priv, theirs, 2, true, [][]byte{pub}),
		control.SignLockStatement(priv, theirs, 3, false, [][]byte{pub}),
	}
	resp := &control.MapResponse{
		Peers: []netmap.Node{signedPeer(t, ours, 1, "laptop", priv), signedPeer(t, ours, 2, "intruder", nil)},
		Lock:  &control.LockConfig{Enabled: false, Chain: replayed},
	}
	kept, _, after, err := verifyPeers(resp, ours, pin)
	if err == nil {
		t.Error("another network's lock version was taken without complaint")
	}
	if after != pin {
		t.Errorf("the pin moved to %+v", after)
	}
	if len(kept) != 1 || kept[0].Name != "laptop" {
		t.Errorf("kept %v, want only the signed peer", kept)
	}
}

// A mesh without a lock is unchanged: everyone is admitted.
func TestNoLockAdmitsEveryone(t *testing.T) {
	ours := network(t)
	resp := &control.MapResponse{Peers: []netmap.Node{signedPeer(t, ours, 1, "a", nil), signedPeer(t, ours, 2, "b", nil)}}
	kept, rejected, pin, err := verifyPeers(resp, ours, nil)
	if len(kept) != 2 || len(rejected) != 0 || pin != nil || err != nil {
		t.Errorf("kept %d, rejected %d, pin %v, err %v", len(kept), len(rejected), pin, err)
	}
}

// A peer signed into another network that trusts the same signing key is not
// one of ours. It used to be admitted: a node's signature covered its ID and
// key and nothing else, so this network's server could show its nodes a
// machine the operator only ever signed into the other one.
func TestAPeerSignedIntoAnotherNetworkIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ours, theirs := network(t), network(t)
	pin := &netmap.LockPin{Epoch: 2, Enabled: true, Keys: [][]byte{pub}}

	resp := &control.MapResponse{Peers: []netmap.Node{
		signedPeer(t, ours, 1, "laptop", priv),
		signedPeer(t, theirs, 2, "from next door", priv),
	}}
	kept, rejected, _, _ := verifyPeers(resp, ours, pin)
	if len(kept) != 1 || kept[0].Name != "laptop" || len(rejected) != 1 {
		t.Errorf("kept %v, want only the peer signed into this network", kept)
	}
}

// A signature made by makima v0.3.0 names no network. A node holding a
// signed lock does not take it — that is the kind another network could
// show — but where the lock was never signed, and is the server's word
// anyway, it still counts, so a network locked under v0.3.0 keeps working
// until it is re-signed.
func TestAnOldSignatureCountsOnlyWhereNoLockIsHeld(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ours := network(t)

	old := signedPeer(t, ours, 1, "laptop", nil)
	old.KeySignature = legacySignature(priv, old.ID, old.Key)

	unsealed := &control.MapResponse{
		Peers: []netmap.Node{old},
		Lock:  &control.LockConfig{Enabled: true, TrustedKeys: []control.SigningKey{{Public: pub}}},
	}
	if kept, _, _, _ := verifyPeers(unsealed, ours, nil); len(kept) != 1 {
		t.Error("an old signature was refused under a lock that was never signed")
	}

	pin := &netmap.LockPin{Epoch: 2, Enabled: true, Keys: [][]byte{pub}}
	if kept, _, _, _ := verifyPeers(&control.MapResponse{Peers: []netmap.Node{old}}, ours, pin); len(kept) != 0 {
		t.Error("an old signature, naming no network, was taken under a signed lock")
	}
}

// legacySignature is a signature as makima v0.3.0 made it: over the node ID
// and key, and nothing else.
func legacySignature(priv ed25519.PrivateKey, id netmap.NodeID, k key.Public) []byte {
	msg := []byte{1}
	msg = binary.BigEndian.AppendUint64(msg, uint64(id))
	msg = append(msg, k[:]...)
	return ed25519.Sign(priv, msg)
}
