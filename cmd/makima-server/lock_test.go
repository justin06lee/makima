package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

// newLockedNetwork is a store with a lock trusting a fresh signing key, and a
// machine registered that nobody has signed yet. It returns the state path
// and the signing key's path.
func newLockedNetwork(t *testing.T, name string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "control.json")
	store, err := control.OpenStore(state)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first := control.SignLockStatement(priv, store.ServerKey().Public(), 1, false, [][]byte{pub})
	if err := store.ApplyLockStatement(first, nil); err != nil {
		t.Fatal(err)
	}
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
	keyPath := filepath.Join(dir, "signing.key")
	if err := writeSigningKey(keyPath, &signingKeyFile{Name: "test", Private: priv, Public: pub}); err != nil {
		t.Fatal(err)
	}
	return state, keyPath
}

// answer makes confirmSigning say yes or no, and records whom it was asked
// about.
func answer(t *testing.T, yes bool) *[]string {
	t.Helper()
	var asked []string
	was := confirmSigning
	confirmSigning = func(fresh []control.UnsignedNode) (bool, error) {
		for _, n := range fresh {
			asked = append(asked, n.Name)
		}
		return yes, nil
	}
	t.Cleanup(func() { confirmSigning = was })
	return &asked
}

// The list of machines to sign is the server's, and the server is what the
// lock defends against. `lock sign` used to sign every one it named, so a
// compromised server needed to forge nothing: it registered a machine of its
// own and waited for the operator's next routine signing. A machine this key
// has never signed is now shown and signed only if somebody agrees.
func TestANewMachineIsSignedOnlyOnceSomebodyAgrees(t *testing.T) {
	state, keyPath := newLockedNetwork(t, "newcomer")
	sock := filepath.Join(filepath.Dir(state), "nobody.sock")
	args := []string{"-state", state, "-socket", sock, "-key", keyPath}

	asked := answer(t, false)
	if err := lockSign(args); err == nil {
		t.Error("declining still reported success")
	}
	if len(*asked) != 1 || (*asked)[0] != "newcomer" {
		t.Errorf("asked about %v, want the newcomer", *asked)
	}
	if st := mustOpen(t, state).LockStatus(); st.Signed != 0 {
		t.Fatalf("declined, and %d machine(s) were signed anyway", st.Signed)
	}

	answer(t, true)
	if err := lockSign(args); err != nil {
		t.Fatal(err)
	}
	if st := mustOpen(t, state).LockStatus(); st.Signed != 1 {
		t.Errorf("agreed, and %d machine(s) signed, want 1", st.Signed)
	}
}

// -yes is for scripts that have checked the list some other way.
func TestYesSignsWithoutAsking(t *testing.T) {
	state, keyPath := newLockedNetwork(t, "newcomer")
	sock := filepath.Join(filepath.Dir(state), "nobody.sock")

	asked := answer(t, false)
	if err := lockSign([]string{"-state", state, "-socket", sock, "-key", keyPath, "-yes"}); err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 0 {
		t.Errorf("-yes still asked about %v", *asked)
	}
	if st := mustOpen(t, state).LockStatus(); st.Signed != 1 {
		t.Errorf("%d machine(s) signed, want 1", st.Signed)
	}
}

// A server handing over bytes that are not the named machine's key in its own
// network — another network's material, or an intruder's key under a trusted
// machine's name — gets no signature at all, even with -yes.
func TestAServerAskingToSignSomethingElseGetsNothing(t *testing.T) {
	dir, err := os.MkdirTemp("", "mk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")

	server, _ := key.NewPrivate()
	laptop, _ := key.NewPrivate()
	intruder, _ := key.NewPrivate()
	pending := []control.UnsignedNode{{
		ID: 3, Name: "laptop", NodeKey: laptop.Public(),
		Material: control.SigningMaterial(server.Public(), 3, intruder.Public()),
	}}

	var signed atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/lock/pending", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(pending)
	})
	mux.HandleFunc("GET /admin/key", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(struct {
			ServerKey key.Public `json:"server_key"`
		}{server.Public()})
	})
	mux.HandleFunc("POST /admin/lock/sign", func(w http.ResponseWriter, r *http.Request) {
		signed.Store(true)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	// -state names a throwaway file, so a socket that failed to answer could
	// never fall through to the machine's own control plane.
	_, keyPath := newLockedNetwork(t, "unused")
	err = lockSign([]string{"-state", filepath.Join(dir, "control.json"), "-socket", sock, "-key", keyPath, "-yes"})
	if err == nil || !strings.Contains(err.Error(), "something other than") {
		t.Errorf("lock sign = %v, want a refusal", err)
	}
	if signed.Load() {
		t.Error("a signature was uploaded for bytes that were not the named machine's")
	}
}

func mustOpen(t *testing.T, state string) *control.Store {
	t.Helper()
	s, err := control.OpenStore(state)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Run from a script, with nobody to ask, signing a machine this key has never
// signed is refused with what to do instead — not taken as a yes.
func TestWithNobodyToAskNothingIsSigned(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	was := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = was })

	laptop, _ := key.NewPrivate()
	ok, err := confirmSigning([]control.UnsignedNode{{ID: 3, Name: "laptop", NodeKey: laptop.Public()}})
	if ok || err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Errorf("with no terminal: %v, %v; want a refusal that mentions -yes", ok, err)
	}
}
