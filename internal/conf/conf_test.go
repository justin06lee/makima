package conf

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

// newFile is a minimally valid static node.
func newFile(t *testing.T) *File {
	t.Helper()
	nodeKey, machineKey, discoKey, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return &File{
		NodeKey:    nodeKey,
		MachineKey: machineKey,
		DiscoKey:   discoKey,
		Self: netmap.Node{
			Name:      "laptop",
			Key:       nodeKey.Public(),
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")},
		},
	}
}

// The one thing this file must get right. It holds all three private keys, and
// a mode that lets anybody else on the machine read it hands them this node's
// identity on the mesh.
func TestSaveWritesKeysUnreadableByAnybodyElse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "makima")
	path := filepath.Join(dir, "node.json")

	if err := Save(path, newFile(t)); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("node.json is mode %04o, want 0600", got)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("the config directory is mode %04o, want 0700", got)
	}
}

// Rewriting must not widen what the first write got right, and the daemon
// rewrites this file on every netmap update.
func TestSaveKeepsTheModeOnRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	f := newFile(t)

	if err := Save(path, f); err != nil {
		t.Fatal(err)
	}
	f.Self.Name = "laptop-renamed"
	if err := Save(path, f); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("after a rewrite node.json is mode %04o, want 0600", got)
	}
}

// Nothing may be left behind holding the same secrets at a wider mode.
func TestSaveLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	if err := Save(filepath.Join(dir, "node.json"), newFile(t)); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "node.json" {
			t.Errorf("Save left %q behind", e.Name())
		}
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	want := newFile(t)
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeKey != want.NodeKey || got.MachineKey != want.MachineKey || got.DiscoKey != want.DiscoKey {
		t.Error("a key did not survive the round trip")
	}
	if got.Self.Name != want.Self.Name {
		t.Errorf("name %q, want %q", got.Self.Name, want.Self.Name)
	}
}

// Three keys, all different. Reusing one would collapse the separation the key
// package exists to keep.
func TestNewIdentityMakesThreeDistinctKeys(t *testing.T) {
	nodeKey, machineKey, discoKey, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []key.Private{nodeKey, machineKey, discoKey} {
		if k.IsZero() {
			t.Fatal("NewIdentity returned a zero key")
		}
	}
	if nodeKey == machineKey || nodeKey == discoKey || machineKey == discoKey {
		t.Error("NewIdentity reused a key")
	}
}

// A private key is a private key wherever it is printed.
func TestPrivateKeysDoNotAppearInAFormattedFile(t *testing.T) {
	f := newFile(t)
	if s := f.NodeKey.String(); strings.Contains(s, f.NodeKey.Base64()) {
		t.Error("a private key printed itself in full")
	}
}

// A file that does not decode must fail rather than come back half-built: a
// node running on half a configuration is a node with no identity.
func TestLoadRejectsRubbish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a malformed config loaded without error")
	}
}

func TestLoadRejectsAStaticNodeWithNoAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	f := newFile(t)
	f.Self.Addresses = nil
	if err := Save(path, f); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a static node with no mesh address loaded without error")
	}
}

// A managed node has no address until it has registered, which is not an error.
func TestLoadAcceptsAManagedNodeWithNoAddressYet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	f := newFile(t)
	f.Self.Addresses = nil
	f.LoginServer = "https://control.example"
	if err := Save(path, f); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("a managed node awaiting its first registration failed to load: %v", err)
	}
}

// The netmap handed to the tunnel carries the private key, and must not be the
// thing that leaks it: whatever else changes, this stays a local-only struct.
func TestNetMapCarriesThePrivateKeyForLocalUseOnly(t *testing.T) {
	f := newFile(t)
	nm := f.NetMap()
	if nm.PrivateKey != f.NodeKey {
		t.Error("NetMap did not carry the node's own key")
	}

	b, err := json.Marshal(nm)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), f.NodeKey.Base64()) {
		t.Error("a marshalled netmap carries the node's private key")
	}
	if strings.Contains(string(b), "private_key") {
		t.Error("a marshalled netmap still has a private_key field")
	}
}
