package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
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
	shownKeys := answerSeal(t, true)

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
	if len(*shownKeys) != 1 {
		t.Errorf("shown %d key(s) to pin, want the one the lock trusts", len(*shownKeys))
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

// TestMain keeps what the lock commands remember out of the home directory
// of whoever runs the tests.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "makima-lock-pins")
	if err != nil {
		panic(err)
	}
	lockPinsPath = func() string { return filepath.Join(dir, "lock-pins.json") }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// pinAt records that version pin of network's lock was signed from here.
func pinAt(t *testing.T, network key.Public, pin *netmap.LockPin) {
	t.Helper()
	p, err := loadPins()
	if err != nil {
		t.Fatal(err)
	}
	p.Networks[network.String()] = pin
	if err := writePrivateJSON(lockPinsPath(), p); err != nil {
		t.Fatal(err)
	}
}

// pinned is what is remembered of network's lock.
func pinned(t *testing.T, network key.Public) *netmap.LockPin {
	t.Helper()
	p, err := pinFor(network)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// answerSeal makes confirmSeal say yes or no, and records the keys it was
// shown.
func answerSeal(t *testing.T, yes bool) *[]control.SigningKey {
	t.Helper()
	var shown []control.SigningKey
	was := confirmSeal
	confirmSeal = func(keys []control.SigningKey, own []byte, enabled bool) (bool, error) {
		shown = append(shown, keys...)
		return yes, nil
	}
	t.Cleanup(func() { confirmSeal = was })
	return &shown
}

// answerChange makes confirmChange say yes or no, and records the keys it was
// shown; nil if it was never asked.
func answerChange(t *testing.T, yes bool) *[][]byte {
	t.Helper()
	var shown [][]byte
	was := confirmChange
	confirmChange = func(epoch uint64, keys []control.SigningKey, own []byte, enabled bool) (bool, error) {
		for _, k := range keys {
			shown = append(shown, k.Public)
		}
		if shown == nil {
			shown = [][]byte{}
		}
		return yes, nil
	}
	t.Cleanup(func() { confirmChange = was })
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

// The old kind of material is checked as closely as the new: bytes that are
// not the named machine's ID and key — a lock version, say — get nothing
// signed. Without the check the operator's key signed whatever the server put
// there.
func TestAServerSlippingSomethingIntoTheOldKindGetsNothing(t *testing.T) {
	server, _ := key.NewPrivate()
	laptop, _ := key.NewPrivate()

	pending := []control.UnsignedNode{{
		ID: 3, Name: "laptop", NodeKey: laptop.Public(),
		Material:       control.SigningMaterial(server.Public(), 3, laptop.Public()),
		LegacyMaterial: []byte("makima lock statement v1\x00 anything the server likes"),
	}}
	if lyingServer(t, server.Public(), pending, "something other than") {
		t.Error("a signature was uploaded")
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
	ids    []netmap.NodeID
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
		var req control.SignatureRequest
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.ids = append(f.ids, req.NodeID)
		f.mu.Unlock()
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

// signingKeyAt writes a signing key file for priv and returns its path.
func signingKeyAt(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing.key")
	sk := &signingKeyFile{Name: "test", Private: priv, Public: priv.Public().(ed25519.PublicKey)}
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
	keyPath := signingKeyAt(t, priv)
	shown := answerChange(t, true)

	if err := lockEnable([]string{"-state", f.state, "-socket", f.sock, "-key", keyPath}, true); err != nil {
		t.Fatal(err)
	}
	if len(*shown) != 1 || !bytes.Equal((*shown)[0], pub) {
		t.Errorf("shown %d key(s) for the first change from here, want the one the signed history trusts", len(*shown))
	}
	posted := f.statements()
	if len(posted) != 1 {
		t.Fatalf("%d versions posted, want 1", len(posted))
	}
	if got := posted[0]; got.Epoch != 2 || !got.Enabled || len(got.Keys) != 1 || !containsKey(got.Keys, pub) {
		t.Errorf("signed version %d, enabled %v, trusting %d key(s): not the signed history plus enforcement", got.Epoch, got.Enabled, len(got.Keys))
	}

	// And it is remembered, as a node remembers its pin.
	if pin := pinned(t, server.Public()); pin == nil || pin.Epoch != 2 {
		t.Errorf("remembered %+v, want version 2", pin)
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
	keyPath := signingKeyAt(t, priv)
	pinAt(t, server.Public(), &netmap.LockPin{Epoch: 2, Keys: [][]byte{pub}})

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
	keyPath := signingKeyAt(t, priv)
	pinAt(t, server.Public(), &netmap.LockPin{Epoch: 3, Enabled: true, Keys: [][]byte{pub}})

	if err := lockEnable([]string{"-state", f.state, "-socket", f.sock, "-key", keyPath}, false); err == nil {
		t.Error("a change was signed on a history missing the version this key last signed")
	}
	if n := len(f.statements()); n != 0 {
		t.Errorf("%d version(s) posted", n)
	}
}

// A lock set up by makima v0.3.0 has no signed history to build a change on,
// so switching it off or on seals it that way — showing the keys it is about
// to pin. Switching an enforced one off used to mean sealing it first, which
// meant signing every machine, just to turn it off.
func TestAnUnsealedLockIsSwitchedOffBySealingItOff(t *testing.T) {
	state, keyPath := oldLockedNetwork(t, "laptop")
	sock := filepath.Join(filepath.Dir(state), "nobody.sock")
	args := []string{"-state", state, "-socket", sock, "-key", keyPath}

	answerSeal(t, false)
	if err := lockEnable(args, false); err == nil {
		t.Error("declining to pin the keys still switched the lock off")
	}
	if st := mustOpen(t, state).LockStatus(); st.Epoch != 0 || !st.Enabled {
		t.Errorf("declined, and the lock is %+v", st)
	}

	shown := answerSeal(t, true)
	asked := answer(t, false)
	if err := lockEnable(args, false); err != nil {
		t.Fatal(err)
	}
	if len(*shown) != 1 || len(*asked) != 0 {
		t.Errorf("shown %d key(s) and asked about machines %v; want the key, and no machine to sign", len(*shown), *asked)
	}
	store := mustOpen(t, state)
	if st := store.LockStatus(); st.Epoch != 1 || st.Enabled {
		t.Errorf("after switching it off: %+v", st)
	}
	if pin := pinned(t, store.ServerKey().Public()); pin == nil || pin.Epoch != 1 {
		t.Errorf("sealing remembered %+v, want version 1", pin)
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
	if pin := pinned(t, store.ServerKey().Public()); pin == nil || pin.Epoch != 3 || !pin.Enabled {
		t.Errorf("remembered %+v, want version 3, enforced", pin)
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
	newKey := signingKeyAt(t, newPriv)
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

// The first change signed from this machine takes the lock's history on
// trust, as a new node does — and a server can make one up that ends where
// the real one does, trusting a key of its own. That used to be signed on
// with no word: on the documented rotation it always was, since the new key
// had no record of its own. What the new version will trust is now shown and
// agreed to first.
func TestAFirstChangeFromHereShowsWhatItWillTrust(t *testing.T) {
	server, _ := key.NewPrivate()
	network := server.Public()
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)

	f := fakeAdmin(t, network)
	f.chain = []control.LockStatement{
		control.SignLockStatement(serverPriv, network, 3, true, [][]byte{serverPub, oldPub, newPub}),
	}
	newKey := signingKeyAt(t, newPriv)
	shown := answerChange(t, false)

	err := lockRemoveKey([]string{"-state", f.state, "-socket", f.sock, "-key", newKey, "-id", (control.SigningKey{Public: oldPub}).ID()})
	if err == nil {
		t.Error("declined, and rm-key reported success")
	}
	if n := len(f.statements()); n != 0 {
		t.Errorf("%d version(s) posted after declining", n)
	}
	if !containsKey(*shown, serverPub) {
		t.Error("the key the new version would trust was not shown")
	}
}

// Rotating from one key file to another keeps what the first signed: the
// record is this machine's, not the key file's, so the new key follows the
// history from where the old one left it, and nothing is taken on trust.
func TestRotatingToANewKeyFileKeepsWhatWasSigned(t *testing.T) {
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
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	newKey := signingKeyAt(t, newPriv)
	if err := lockAddKey(at(oldKey, "-public", base64.RawURLEncoding.EncodeToString(newPub))); err != nil {
		t.Fatal(err)
	}
	old, _ := readSigningKey(oldKey)

	shown := answerChange(t, false)
	if err := lockRemoveKey(at(newKey, "-id", (control.SigningKey{Public: old.Public}).ID())); err != nil {
		t.Fatalf("rm-key with the new key: %v", err)
	}
	if *shown != nil {
		t.Error("the new key was asked to take the history on trust; what the old one signed was not kept")
	}
}

// Sealing is for a lock never signed. One signed from this machine before is
// not that, whatever the server says: sealing it again used to sign a first
// version of the server's choosing and wind what this machine remembered back
// to it, so the next change built on a history the server made up.
func TestALockSignedFromHereIsNotSealedAgain(t *testing.T) {
	server, _ := key.NewPrivate()
	network := server.Public()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, _, _ := ed25519.GenerateKey(rand.Reader)

	f := fakeAdmin(t, network)
	f.status = control.LockStatus{Epoch: 0, TrustedKeys: []control.SigningKey{{Public: pub, Name: "laptop"}, {Public: serverPub, Name: "laptop"}}}
	keyPath := signingKeyAt(t, priv)
	pinAt(t, network, &netmap.LockPin{Epoch: 3, Enabled: true, Keys: [][]byte{pub}})

	if err := lockSeal([]string{"-state", f.state, "-socket", f.sock, "-key", keyPath, "-yes"}); err == nil {
		t.Error("a lock signed from here was sealed again")
	}
	if n := len(f.statements()); n != 0 {
		t.Errorf("%d version(s) posted", n)
	}
	if pin := pinned(t, network); pin == nil || pin.Epoch != 3 {
		t.Errorf("what was signed from here is now %+v, want version 3", pin)
	}
}

// rm-key lists every machine it would sign again and asks, like lock sign:
// the list is the server's, and whether the dropped key once signed a
// machine says nothing about whether it is still yours — the server can keep
// an old signature for one expired or forgotten since.
func TestRemovingAKeyAsksAboutTheMachinesItWouldSign(t *testing.T) {
	server, _ := key.NewPrivate()
	network := server.Public()
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	laptop, _ := key.NewPrivate()
	rogue, _ := key.NewPrivate()

	f := fakeAdmin(t, network)
	f.chain = []control.LockStatement{
		control.SignLockStatement(oldPriv, network, 1, true, [][]byte{oldPub}),
		control.SignLockStatement(oldPriv, network, 2, true, [][]byte{oldPub, newPub}),
	}
	entry := func(id netmap.NodeID, name string, k key.Public) control.UnsignedNode {
		return control.UnsignedNode{ID: id, Name: name, NodeKey: k,
			Material:       control.SigningMaterial(network, id, k),
			LegacyMaterial: control.LegacySigningMaterial(id, k)}
	}
	f.pending = []control.UnsignedNode{entry(1, "laptop", laptop.Public()), entry(99, "rogue", rogue.Public())}
	newKey := signingKeyAt(t, newPriv)
	pinAt(t, network, &netmap.LockPin{Epoch: 2, Enabled: true, Keys: [][]byte{oldPub, newPub}})

	asked := answer(t, false)
	if err := lockRemoveKey([]string{"-state", f.state, "-socket", f.sock, "-key", newKey, "-id", (control.SigningKey{Public: oldPub}).ID()}); err == nil {
		t.Error("declined, and rm-key reported success")
	}
	if len(*asked) != 2 {
		t.Errorf("asked about %v, want every machine listed", *asked)
	}
	if f.signed.Load() || len(f.statements()) != 0 {
		t.Error("declined, and something was signed")
	}
}

// -yes on rm-key agrees to the machines listed, and to nothing else: with no
// record of the lock here, what the new version will trust is still shown.
// It used to skip that too, and the documented rotation — rm-key with the new
// key, often from another machine — signed a history the server made up.
func TestRemovingAKeyWithYesStillShowsWhatTheLockWillTrust(t *testing.T) {
	server, _ := key.NewPrivate()
	network := server.Public()
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)

	f := fakeAdmin(t, network)
	f.chain = []control.LockStatement{
		control.SignLockStatement(serverPriv, network, 3, true, [][]byte{serverPub, oldPub, newPub}),
	}
	newKey := signingKeyAt(t, newPriv)
	shown := answerChange(t, false)

	_ = lockRemoveKey([]string{"-state", f.state, "-socket", f.sock, "-key", newKey, "-id", (control.SigningKey{Public: oldPub}).ID(), "-yes"})
	if *shown == nil {
		t.Error("-yes skipped showing what the new version would trust")
	}
	if n := len(f.statements()); n != 0 {
		t.Errorf("%d version(s) posted after declining", n)
	}
}

// Enabling a lock that was never sealed seals it enforced, which signs every
// machine — and they are asked about. enable had a -yes that signed whatever
// the server listed, unshown.
func TestEnablingAnUnsealedLockAsksAboutEveryMachine(t *testing.T) {
	state, keyPath := oldLockedNetwork(t, "laptop")
	sock := filepath.Join(filepath.Dir(state), "nobody.sock")

	answerSeal(t, true)
	asked := answer(t, false)
	if err := lockEnable([]string{"-state", state, "-socket", sock, "-key", keyPath}, true); err == nil {
		t.Error("declined the machines, and enable reported success")
	}
	if len(*asked) != 1 {
		t.Errorf("asked about %v, want the laptop", *asked)
	}
	if st := mustOpen(t, state).LockStatus(); st.Epoch != 0 {
		t.Errorf("declined, and the lock is at version %d", st.Epoch)
	}
}

// A mistyped -id is found before anything is signed, not after.
func TestRemovingAKeyThatIsNotTrustedSignsNothing(t *testing.T) {
	server, _ := key.NewPrivate()
	network := server.Public()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	fresh, _ := key.NewPrivate()

	f := fakeAdmin(t, network)
	both := [][]byte{pub, other}
	f.chain = []control.LockStatement{control.SignLockStatement(priv, network, 1, true, both)}
	f.pending = []control.UnsignedNode{{ID: 5, Name: "fresh", NodeKey: fresh.Public(),
		Material: control.SigningMaterial(network, 5, fresh.Public()), LegacyMaterial: control.LegacySigningMaterial(5, fresh.Public())}}
	keyPath := signingKeyAt(t, priv)
	pinAt(t, network, &netmap.LockPin{Epoch: 1, Enabled: true, Keys: both})

	if err := lockRemoveKey([]string{"-state", f.state, "-socket", f.sock, "-key", keyPath, "-id", "nosuchkeyid0", "-yes"}); err == nil {
		t.Error("removing a key the lock does not trust succeeded")
	}
	if f.signed.Load() {
		t.Error("machines were signed before the -id was found to be wrong")
	}
}

// The key signing a change cannot be the one it drops: the machines it would
// re-sign would be signed by a key that is about to stop counting.
func TestAKeyDoesNotSignItsOwnRemoval(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "control.json")
	keyPath := filepath.Join(dir, "signing.key")
	common := []string{"-state", state, "-socket", filepath.Join(dir, "nobody.sock"), "-key", keyPath}
	if err := lockInit(common); err != nil {
		t.Fatal(err)
	}
	sk, _ := readSigningKey(keyPath)
	err := lockRemoveKey(append(common, "-id", (control.SigningKey{Public: sk.Public}).ID()))
	if err == nil || !strings.Contains(err.Error(), "a key that stays") {
		t.Errorf("rm-key of the signing key itself = %v", err)
	}
}

// 'lock forget' drops what this machine remembers of the lock, so 'lock
// init' can start a new one. A server that says there is no lock, where one
// was signed from here and not forgotten, is refused unless told to start
// over: it may be hiding the lock.
func TestStartingOverIsForgettingFirst(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "control.json")
	sock := filepath.Join(dir, "nobody.sock")
	common := []string{"-state", state, "-socket", sock}
	keyPath := filepath.Join(dir, "signing.key")

	if err := lockInit(append(common, "-key", keyPath)); err != nil {
		t.Fatal(err)
	}
	network := mustOpen(t, state).ServerKey().Public()
	if pin := pinned(t, network); pin == nil || pin.Epoch != 1 {
		t.Fatalf("init remembered %+v, want version 1", pin)
	}

	if err := lockForget(common); err != nil {
		t.Fatal(err)
	}
	if pin := pinned(t, network); pin != nil {
		t.Errorf("forget left %+v remembered", pin)
	}
	if err := lockInit(append(common, "-key", filepath.Join(dir, "second.key"))); err != nil {
		t.Fatalf("init after forget: %v", err)
	}

	// Now the server loses the lock without being told to forget it. Not
	// even -force starts over — -force is about the key file, and starting
	// over would overwrite the key the nodes holding the lock trust.
	store := mustOpen(t, state)
	if err := store.ForgetLock(); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(dir, "second.key")
	before, _ := os.ReadFile(second)
	if err := lockInit(append(common, "-key", second, "-force")); err == nil {
		t.Error("init -force started over on a lock signed from here and never forgotten")
	}
	if after, _ := os.ReadFile(second); !bytes.Equal(before, after) {
		t.Error("the refused init overwrote the key file")
	}
	if out := capture(t, func() { lockStatus(common) }); !strings.Contains(out, "hiding it") {
		t.Errorf("status said %q, want to be told the server lost or is hiding the lock", out)
	}

	// Letting go of this machine's record is its own, deliberate step.
	if err := lockForget(append(common, "-local")); err != nil {
		t.Fatal(err)
	}
	if err := lockInit(append(common, "-key", filepath.Join(dir, "third.key"))); err != nil {
		t.Errorf("init after forget -local: %v", err)
	}
}

// capture runs fn and returns what it printed.
func capture(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	was := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stdout = was
	return <-done
}

// A key file is written once, by 'lock init', and never again: one behind a
// symlink stays a symlink, one on read-only media is fine, and a command run
// under sudo does not leave it root's.
func TestAKeyFileIsNotRewrittenByAChange(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "control.json")
	real := filepath.Join(dir, "stick", "signing.key")
	link := filepath.Join(dir, "signing.key")
	common := []string{"-state", state, "-socket", filepath.Join(dir, "nobody.sock")}

	if err := lockInit(append(common, "-key", real)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(real)
	if err := lockEnable(append(common, "-key", link), true); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlinked key file was replaced")
	}
	if after, _ := os.ReadFile(real); !bytes.Equal(before, after) {
		t.Error("the key file was rewritten by a lock change")
	}
}

// What this machine remembers never goes backwards: a version older than the
// one signed here is not taken in its place, however it arrives.
func TestWhatWasSignedHereNeverGoesBackwards(t *testing.T) {
	server, _ := key.NewPrivate()
	network := server.Public()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pinAt(t, network, &netmap.LockPin{Epoch: 5, Enabled: true, Keys: [][]byte{pub}})

	rememberPin(network, control.SignLockStatement(priv, network, 3, false, [][]byte{pub}))
	if pin := pinned(t, network); pin == nil || pin.Epoch != 5 || !pin.Enabled {
		t.Errorf("remembered %+v after an older version, want version 5 still", pin)
	}
	rememberPin(network, control.SignLockStatement(priv, network, 6, false, [][]byte{pub}))
	if pin := pinned(t, network); pin == nil || pin.Epoch != 6 {
		t.Errorf("remembered %+v after a newer version, want version 6", pin)
	}
}

// A server showing a different version at the number signed from here has
// rewritten history. Nothing was ever built on it, but it used to be stepped
// past without a word; it is refused and said.
func TestADifferentVersionAtTheOneSignedHereIsRefused(t *testing.T) {
	server, _ := key.NewPrivate()
	network := server.Public()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	f := fakeAdmin(t, network)
	f.chain = []control.LockStatement{
		control.SignLockStatement(priv, network, 1, false, [][]byte{pub}),
		control.SignLockStatement(priv, network, 2, false, [][]byte{pub}),
	}
	keyPath := signingKeyAt(t, priv)
	pinAt(t, network, &netmap.LockPin{Epoch: 2, Enabled: true, Keys: [][]byte{pub}})

	err := lockEnable([]string{"-state", f.state, "-socket", f.sock, "-key", keyPath}, false)
	if err == nil || !strings.Contains(err.Error(), "rewritten") {
		t.Errorf("lock disable over a rewritten version 2 = %v", err)
	}

	// The same number and state, but other keys, is as much a rewrite.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	pinAt(t, network, &netmap.LockPin{Epoch: 2, Enabled: false, Keys: [][]byte{pub, other}})
	err = lockEnable([]string{"-state", f.state, "-socket", f.sock, "-key", keyPath}, true)
	if err == nil || !strings.Contains(err.Error(), "rewritten") {
		t.Errorf("lock enable over a version 2 with other keys = %v", err)
	}
	if n := len(f.statements()); n != 0 {
		t.Errorf("%d version(s) posted", n)
	}
}

// Names shown in the lock prompts are the server's, and a control character
// in one could erase or rewrite the lines the prompt asks to be checked.
func TestNamesInPromptsCannotRewriteThem(t *testing.T) {
	if got := printable("laptop\r\x1b[2K\x1b[1A‮"); got != "laptop[2K[1A" {
		t.Errorf("printable kept %q", got)
	}
	out := capture(t, func() {
		printKeys([]control.SigningKey{{Public: make([]byte, 32), Name: "evil\x1b[1A\x1b[2K"}}, nil)
	})
	if strings.ContainsRune(out, '\x1b') {
		t.Errorf("printKeys wrote an escape: %q", out)
	}
}

// With nobody at a terminal, the look at what a lock version will trust is
// refused — and the refusal does not point at a -yes that cannot stand in
// for it.
func TestWithNobodyToLookAtTheKeysNothingIsSigned(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	was := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = was })

	var ok bool
	capture(t, func() {
		ok, err = confirmChange(2, []control.SigningKey{{Public: make([]byte, 32)}}, nil, true)
	})
	if ok || err == nil || strings.Contains(err.Error(), "-yes") {
		t.Errorf("with no terminal: %v, %v; want a refusal that does not offer -yes", ok, err)
	}
}
