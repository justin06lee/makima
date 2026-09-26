package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
)

// oldLockedNetwork writes a control plane's state as makima v0.3.0 left it
// with a lock enforced: nodes signed the old way, over their ID and key and
// naming no network, and a lock whose versions were never signed. It returns
// the state path and the signing key's path.
func oldLockedNetwork(t *testing.T, names ...string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "control.json")

	store, err := control.OpenStore(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		auth, err := store.MintAuthKey(false, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		machine, _ := key.NewPrivate()
		node, _ := key.NewPrivate()
		disco, _ := key.NewPrivate()
		if _, err := store.Register(machine.Public(), &control.RegisterRequest{
			Name: name, NodeKey: node.Public(), DiscoKey: disco.Public(), AuthKey: auth.Secret,
		}); err != nil {
			t.Fatal(err)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "signing.key")
	if err := writeSigningKey(keyPath, &signingKeyFile{Name: "test", Private: priv, Public: pub}); err != nil {
		t.Fatal(err)
	}

	// The lock and the old signatures go into the file itself: nothing in
	// this makima makes either any more.
	b, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for i, n := range store.Nodes() {
		msg := []byte{1}
		msg = binary.BigEndian.AppendUint64(msg, uint64(n.ID))
		msg = append(msg, n.NodeKey[:]...)
		raw["nodes"].([]any)[i].(map[string]any)["key_signature"] = ed25519.Sign(priv, msg)
	}
	raw["lock"] = map[string]any{
		"trusted_keys": []any{map[string]any{"public": []byte(pub), "name": "test", "added": time.Now()}},
		"enabled":      true,
		"created":      time.Now(),
	}
	if b, err = json.Marshal(raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return state, keyPath
}

// Sealing a lock from makima v0.3.0 is where its nodes start holding the
// server to it, and a node holding a signed lock takes only signatures that
// name its network. The old nodes have none, so sealing signs them first —
// otherwise an enforced lock could not be sealed at all, and a node that
// sealed it anyway would refuse every peer.
func TestSealingAnOldLockSignsItsNodesForThisNetwork(t *testing.T) {
	state, keyPath := oldLockedNetwork(t, "laptop", "desktop")
	sock := filepath.Join(filepath.Dir(state), "nobody.sock")

	if err := lockSeal([]string{"-state", state, "-socket", sock, "-key", keyPath}); err != nil {
		t.Fatalf("seal: %v", err)
	}

	store, err := control.OpenStore(state)
	if err != nil {
		t.Fatal(err)
	}
	st := store.LockStatus()
	if st.Epoch != 1 || !st.Enabled || st.Signed != 2 || st.Unsigned != 0 {
		t.Fatalf("after sealing: %+v", st)
	}

	network := store.ServerKey().Public()
	pin, err := control.AdvanceLock(network, nil, store.LockChain())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range store.Nodes() {
		if err := control.VerifyPinned(network, pin, n.ID, n.NodeKey, n.NetworkSignature); err != nil {
			t.Errorf("a node holding the sealed lock refuses %s: %v", n.Name, err)
		}
		if len(n.KeySignature) == 0 {
			t.Errorf("%s lost its old signature, which machines still on v0.3.0 check", n.Name)
		}
	}
}
