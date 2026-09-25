package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

func signedPeer(t *testing.T, id netmap.NodeID, name string, signer ed25519.PrivateKey) netmap.Node {
	t.Helper()
	k, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	p := netmap.Node{ID: id, Name: name, Key: k.Public()}
	if signer != nil {
		p.KeySignature = control.SignNodeKey(signer, id, p.Key)
	}
	return p
}

// The control plane turning against the network: it drops the lock from the
// netmap, or sends it switched off without a signed version saying so, and
// introduces a peer of its own. A node holding the lock refuses the peer
// either way. Before, the node took the lock's state from each netmap, so
// either move admitted anyone.
func TestPinnedLockOutlivesTheServerSayingOtherwise(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pin := &netmap.LockPin{Epoch: 2, Enabled: true, Keys: [][]byte{pub}}

	real := signedPeer(t, 1, "laptop", priv)
	invented := signedPeer(t, 2, "intruder", nil)

	for name, lock := range map[string]*control.LockConfig{
		"no lock":        nil,
		"switched off":   {Enabled: false},
		"rogue key only": {Enabled: true, TrustedKeys: []control.SigningKey{{Public: make([]byte, 32)}}},
	} {
		resp := &control.MapResponse{Peers: []netmap.Node{real, invented}, Lock: lock}
		kept, rejected, after, _ := verifyPeers(resp, pin)
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
	chain := []control.LockStatement{
		control.SignLockStatement(priv, 1, false, [][]byte{pub}),
		control.SignLockStatement(priv, 2, true, [][]byte{pub}),
	}
	resp := &control.MapResponse{
		Peers: []netmap.Node{signedPeer(t, 1, "laptop", priv), signedPeer(t, 2, "intruder", nil)},
		Lock:  &control.LockConfig{Enabled: true, Chain: chain},
	}
	kept, _, pin, err := verifyPeers(resp, nil)
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

// A mesh without a lock is unchanged: everyone is admitted.
func TestNoLockAdmitsEveryone(t *testing.T) {
	resp := &control.MapResponse{Peers: []netmap.Node{signedPeer(t, 1, "a", nil), signedPeer(t, 2, "b", nil)}}
	kept, rejected, pin, err := verifyPeers(resp, nil)
	if len(kept) != 2 || len(rejected) != 0 || pin != nil || err != nil {
		t.Errorf("kept %d, rejected %d, pin %v, err %v", len(kept), len(rejected), pin, err)
	}
}
