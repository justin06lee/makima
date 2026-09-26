package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
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
// sealed it anyway would refuse every peer. They are shown and agreed to like
// any others: an old signature is not proof the server has not made one up.
func TestSealingAnOldLockSignsItsNodesForThisNetwork(t *testing.T) {
	state, keyPath := oldLockedNetwork(t, "laptop", "desktop")
	sock := filepath.Join(filepath.Dir(state), "nobody.sock")
	asked := answer(t, true)
	pinned := answerSeal(t, true)

	if err := lockSeal([]string{"-state", state, "-socket", sock, "-key", keyPath}); err != nil {
		t.Fatalf("seal: %v", err)
	}

	store, err := control.OpenStore(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 2 {
		t.Errorf("asked about %v, want both machines", *asked)
	}
	if len(*pinned) != 1 {
		t.Errorf("shown %d key(s) to pin, want the one the lock trusts", len(*pinned))
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

// answerSeal makes confirmSeal say yes or no, and records the keys it was
// shown.
func answerSeal(t *testing.T, yes bool) *[]control.SigningKey {
	t.Helper()
	var shown []control.SigningKey
	was := confirmSeal
	confirmSeal = func(keys []control.SigningKey) (bool, error) {
		shown = append(shown, keys...)
		return yes, nil
	}
	t.Cleanup(func() { confirmSeal = was })
	return &shown
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
	store := mustOpen(t, state)
	if st := store.LockStatus(); st.Signed != 1 {
		t.Errorf("agreed, and %d machine(s) signed, want 1", st.Signed)
	}
	// And the old kind, for machines still on v0.3.0.
	if n := store.Nodes()[0]; len(n.KeySignature) == 0 || len(store.PendingSignatures()) != 0 {
		t.Error("the machine was not signed the old way too")
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
// network — an intruder's key under a known machine's name, or material for
// another network than the one it says it is — gets no signature at all, even
// with -yes. One still asking for the old kind is told what is wrong, rather
// than accused of lying.
func TestAServerAskingToSignSomethingElseGetsNothing(t *testing.T) {
	server, _ := key.NewPrivate()
	elsewhere, _ := key.NewPrivate()
	laptop, _ := key.NewPrivate()
	intruder, _ := key.NewPrivate()

	for _, c := range []struct {
		name     string
		material []byte
		want     string
	}{
		{"an intruder's key", control.SigningMaterial(server.Public(), 3, intruder.Public()), "something other than"},
		{"another network", control.SigningMaterial(elsewhere.Public(), 3, laptop.Public()), "something other than"},
		{"an older server", control.LegacySigningMaterial(3, laptop.Public()), "older makima"},
	} {
		t.Run(c.name, func(t *testing.T) {
			pending := []control.UnsignedNode{{ID: 3, Name: "laptop", NodeKey: laptop.Public(), Material: c.material}}
			signed := lyingServer(t, server.Public(), pending, c.want)
			if signed {
				t.Error("a signature was uploaded")
			}
		})
	}
}

// lyingServer runs a fake control plane's admin socket that reports network
// as its key and pending as the machines to sign, runs lock sign -yes against
// it, and reports whether anything was uploaded. The error has to contain
// want.
func lyingServer(t *testing.T, network key.Public, pending []control.UnsignedNode, want string) bool {
	t.Helper()
	fake := fakeAdmin(t, network)
	fake.pending = pending

	_, keyPath := newLockedNetwork(t, "unused")
	err := lockSign([]string{"-state", fake.state, "-socket", fake.sock, "-key", keyPath, "-yes"})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("lock sign = %v, want a refusal saying %q", err, want)
	}
	return fake.signed.Load()
}

// fake is a control plane's admin socket that says what a test tells it to,
// and records what the signing tool sends it.
type fake struct {
	sock, state string

	status  control.LockStatus
	chain   []control.LockStatement
	pending []control.UnsignedNode

	signed atomic.Bool
	mu     sync.Mutex
	posted []control.LockStatement
}

// fakeAdmin starts one answering as the control plane whose key is network.
// Its -state names a throwaway file, so a socket that failed to answer could
// never fall through to the machine's own control plane.
func fakeAdmin(t *testing.T, network key.Public) *fake {
	t.Helper()
	dir, err := os.MkdirTemp("", "mk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fake{sock: filepath.Join(dir, "admin.sock"), state: filepath.Join(dir, "control.json")}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/key", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(struct {
			ServerKey key.Public `json:"server_key"`
		}{network})
	})
	mux.HandleFunc("GET /admin/lock", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(f.status)
	})
	mux.HandleFunc("GET /admin/lock/chain", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(f.chain)
	})
	mux.HandleFunc("GET /admin/lock/pending", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(f.pending)
	})
	mux.HandleFunc("POST /admin/lock/sign", func(w http.ResponseWriter, r *http.Request) {
		f.signed.Store(true)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /admin/lock/statement", func(w http.ResponseWriter, r *http.Request) {
		var req control.LockStatementRequest
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.posted = append(f.posted, req.Statement)
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return f
}

func (f *fake) statements() []control.LockStatement {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]control.LockStatement(nil), f.posted...)
}

// signingKeyAt writes a signing key file for priv, with the versions it has
// signed, and returns its path.
func signingKeyAt(t *testing.T, priv ed25519.PrivateKey, networks map[string]*netmap.LockPin) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing.key")
	sk := &signingKeyFile{Name: "test", Private: priv, Public: priv.Public().(ed25519.PublicKey), Networks: networks}
	if err := writeSigningKey(path, sk); err != nil {
		t.Fatal(err)
	}
	return path
}

// A lock change is built on the lock's signed versions, not on what the
// server says they add up to. Before, lock enable signed whatever key list
// the server reported: a compromised one reported a key of its own beside
// the operator's, and the operator's next change signed it in — a version
// every node would take, since the operator's key signed it.
func TestALockChangeIsBuiltOnTheSignedHistoryNotTheServersWord(t *testing.T) {
	server, _ := key.NewPrivate()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	attacker, _, _ := ed25519.GenerateKey(rand.Reader)

	f := fakeAdmin(t, server.Public())
	f.chain = []control.LockStatement{control.SignLockStatement(priv, server.Public(), 1, false, [][]byte{pub})}
	f.status = control.LockStatus{Epoch: 1, TrustedKeys: []control.SigningKey{{Public: pub}, {Public: attacker}}}
	keyPath := signingKeyAt(t, priv, nil)

	if err := lockEnable([]string{"-state", f.state, "-socket", f.sock, "-key", keyPath}, true); err != nil {
		t.Fatal(err)
	}
	posted := f.statements()
	if len(posted) != 1 {
		t.Fatalf("%d versions posted, want 1", len(posted))
	}
	if got := posted[0]; got.Epoch != 2 || !got.Enabled || len(got.Keys) != 1 || !containsKey(got.Keys, pub) {
		t.Errorf("signed version %d, enabled %v, trusting %d key(s): not the signed history plus enforcement", got.Epoch, got.Enabled, len(got.Keys))
	}

	// And the key file now remembers it, as a node remembers its pin.
	sk, err := readSigningKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if pin := sk.Networks[server.Public().String()]; pin == nil || pin.Epoch != 2 {
		t.Errorf("the key file remembers %+v, want version 2", pin)
	}
}

// Once this key has signed a version of a network's lock, a history that does
// not follow from it — one the server wrote itself, starting over with its own
// key beside the operator's — gets nothing signed.
func TestARewrittenHistoryGetsNothingSigned(t *testing.T) {
	server, _ := key.NewPrivate()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	attackerPub, attacker, _ := ed25519.GenerateKey(rand.Reader)

	f := fakeAdmin(t, server.Public())
	both := [][]byte{pub, attackerPub}
	f.chain = []control.LockStatement{
		control.SignLockStatement(attacker, server.Public(), 1, false, both),
		control.SignLockStatement(attacker, server.Public(), 2, false, both),
		control.SignLockStatement(attacker, server.Public(), 3, false, both),
	}
	f.status = control.LockStatus{Epoch: 3, TrustedKeys: []control.SigningKey{{Public: pub}, {Public: attackerPub}}}
	keyPath := signingKeyAt(t, priv, map[string]*netmap.LockPin{
		server.Public().String(): {Epoch: 2, Keys: [][]byte{pub}},
	})

	if err := lockEnable([]string{"-state", f.state, "-socket", f.sock, "-key", keyPath}, true); err == nil {
		t.Error("a change was signed on a history that does not follow from the one this key signed")
	}
	if n := len(f.statements()); n != 0 {
		t.Errorf("%d version(s) posted", n)
	}
}

// Nor is a history cut short: a server hiding the versions after one it
// would rather the next change were built on.
func TestAHiddenVersionGetsNothingSigned(t *testing.T) {
	server, _ := key.NewPrivate()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	f := fakeAdmin(t, server.Public())
	f.chain = []control.LockStatement{
		control.SignLockStatement(priv, server.Public(), 1, false, [][]byte{pub}),
		control.SignLockStatement(priv, server.Public(), 2, true, [][]byte{pub}),
	}
	f.status = control.LockStatus{Epoch: 2, Enabled: true, TrustedKeys: []control.SigningKey{{Public: pub}}}
	keyPath := signingKeyAt(t, priv, map[string]*netmap.LockPin{
		server.Public().String(): {Epoch: 3, Enabled: true, Keys: [][]byte{pub}},
	})

	if err := lockEnable([]string{"-state", f.state, "-socket", f.sock, "-key", keyPath}, false); err == nil {
		t.Error("a change was signed on a history missing the version this key last signed")
	}
	if n := len(f.statements()); n != 0 {
		t.Errorf("%d version(s) posted", n)
	}
}

// A lock set up by makima v0.3.0 has no signed history to build a change on.
// It is sealed first, which shows what it is about to pin.
func TestAnUnsealedLockIsSealedBeforeItIsChanged(t *testing.T) {
	state, keyPath := oldLockedNetwork(t, "laptop")
	sock := filepath.Join(filepath.Dir(state), "nobody.sock")
	args := []string{"-state", state, "-socket", sock, "-key", keyPath}

	err := lockEnable(args, false)
	if err == nil || !strings.Contains(err.Error(), "seal it first") {
		t.Errorf("disabling an unsealed lock = %v, want to be told to seal it", err)
	}

	answerSeal(t, false)
	if err := lockSeal(args); err == nil {
		t.Error("declining to pin the keys still sealed the lock")
	}
	if st := mustOpen(t, state).LockStatus(); st.Epoch != 0 {
		t.Errorf("declined, and the lock is at version %d", st.Epoch)
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

// The ordinary run of commands, against a store: each change builds on the
// version the one before signed, and the key file keeps up.
func TestTheLockCommandsFollowOneAnother(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "control.json")
	keyPath := filepath.Join(dir, "signing.key")
	sock := filepath.Join(dir, "nobody.sock")
	common := []string{"-state", state, "-socket", sock, "-key", keyPath}

	if err := lockInit(append(common, "-name", "laptop")); err != nil {
		t.Fatalf("init: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := lockAddKey(append(common, "-public", base64.RawURLEncoding.EncodeToString(other), "-name", "backup")); err != nil {
		t.Fatalf("add-key: %v", err)
	}
	if err := lockEnable(common, true); err != nil {
		t.Fatalf("enable: %v", err)
	}

	store := mustOpen(t, state)
	if st := store.LockStatus(); st.Epoch != 3 || !st.Enabled || len(st.TrustedKeys) != 2 {
		t.Errorf("after init, add-key and enable: %+v", st)
	}
	sk, err := readSigningKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if pin := sk.Networks[store.ServerKey().Public().String()]; pin == nil || pin.Epoch != 3 || !pin.Enabled {
		t.Errorf("the key file remembers %+v, want version 3, enforced", pin)
	}
}

// Rotating the signing key while the lock is enforced: trust the new key
// with the old, then drop the old with the new. Dropping it used to be
// refused — every machine was signed by the old key only, so the version
// would have them all rejected — and lock sign could not help, since the
// old key still counted and it found nothing to sign. rm-key now signs
// again, with the key making the change, every machine that only the key
// being dropped had signed.
func TestTheSigningKeyCanBeRotatedWhileEnforced(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "control.json")
	sock := filepath.Join(dir, "nobody.sock")
	oldKey := filepath.Join(dir, "old.key")
	at := func(keyPath string, extra ...string) []string {
		return append([]string{"-state", state, "-socket", sock, "-key", keyPath}, extra...)
	}

	if err := lockInit(at(oldKey, "-name", "old")); err != nil {
		t.Fatal(err)
	}
	store := mustOpen(t, state)
	auth, _ := store.MintAuthKey(false, time.Hour)
	machine, _ := key.NewPrivate()
	node, _ := key.NewPrivate()
	if _, err := store.Register(machine.Public(), &control.RegisterRequest{Name: "laptop", NodeKey: node.Public(), AuthKey: auth.Secret}); err != nil {
		t.Fatal(err)
	}
	if err := lockSign(at(oldKey, "-yes")); err != nil {
		t.Fatal(err)
	}
	if err := lockEnable(at(oldKey), true); err != nil {
		t.Fatal(err)
	}

	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	newKey := signingKeyAt(t, newPriv, nil)
	if err := lockAddKey(at(oldKey, "-public", base64.RawURLEncoding.EncodeToString(newPub), "-name", "new")); err != nil {
		t.Fatal(err)
	}
	old, err := readSigningKey(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	asked := answer(t, true)
	if err := lockRemoveKey(at(newKey, "-id", (control.SigningKey{Public: old.Public}).ID())); err != nil {
		t.Fatalf("dropping the old key: %v", err)
	}
	if len(*asked) != 1 {
		t.Errorf("asked about %v, want the laptop", *asked)
	}

	after := mustOpen(t, state)
	st := after.LockStatus()
	if len(st.TrustedKeys) != 1 || !bytes.Equal(st.TrustedKeys[0].Public, newPub) || st.Signed != 1 || !st.Enabled {
		t.Errorf("after rotating: %+v", st)
	}
}
