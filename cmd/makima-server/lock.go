package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/justin06lee/makima/internal/control"
)

// The network lock's private key is the one secret in makima that must not
// live on the control server, because the server is the thing it defends
// against. So it lives in a file next to whoever administers the mesh, and
// `lock sign` is a local operation that uploads only signatures.
//
// This is also why signing is a separate step from registration rather than
// automatic. A mesh where the server could obtain signatures on demand would
// have a lock whose key it effectively holds.

// DefaultSigningKeyPath is where the operator's signing key lives.
//
// Under the user's home directory rather than /var/lib, and deliberately not
// beside the control plane's state: the whole guarantee depends on these two
// being separable, and putting them in the same directory invites a backup
// script to collect both.
func DefaultSigningKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".makima-signing.key"
	}
	return filepath.Join(home, ".config", "makima", "signing.key")
}

// signingKeyFile is the on-disk form.
type signingKeyFile struct {
	Name    string `json:"name"`
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

func lockCmd(args []string) error {
	if len(args) == 0 {
		return lockStatus(nil)
	}
	switch args[0] {
	case "status":
		return lockStatus(args[1:])
	case "init":
		return lockInit(args[1:])
	case "add-key":
		return lockAddKey(args[1:])
	case "rm-key":
		return lockRemoveKey(args[1:])
	case "sign":
		return lockSign(args[1:])
	case "enable":
		return lockEnable(args[1:], true)
	case "disable":
		return lockEnable(args[1:], false)
	case "seal":
		return lockSeal(args[1:])
	case "forget":
		return lockForget(args[1:])
	default:
		return fmt.Errorf("unknown lock subcommand %q (try: status, init, sign, enable, disable, add-key, rm-key, seal, forget)", args[0])
	}
}

func lockStatus(args []string) error {
	af := newAdminFlags("lock status")
	t, err := af.open(args)
	if err != nil {
		return err
	}

	var st control.LockStatus
	if t.live() {
		st, err = t.admin.LockStatus()
	} else {
		st = t.store.LockStatus()
	}
	if err != nil {
		return err
	}

	if len(st.TrustedKeys) == 0 {
		fmt.Print("network lock is not set up\n\n")
		fmt.Print("without it, this control server is trusted to say who belongs to the mesh:\n")
		fmt.Print("it cannot read anyone's traffic, but it could introduce a node you never authorised.\n\n")
		fmt.Print("set it up with:\n  makima-server lock init\n")
		return nil
	}

	state := "configured but NOT enforced"
	if st.Enabled {
		state = "enabled and enforced by every node"
	}
	fmt.Printf("network lock: %s (version %d)\n\n", state, st.Epoch)
	if st.Epoch == 0 {
		fmt.Print("this lock was set up before its versions were signed, so nodes cannot hold\n")
		fmt.Print("this server to it: a compromised server could still switch it off. seal it with\n")
		fmt.Print("  makima-server lock seal\n\n")
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprint(w, "ID\tNAME\tADDED\n")
	for _, k := range st.TrustedKeys {
		fmt.Fprintf(w, "%s\t%s\t%s\n", k.ID(), k.Name, k.Added.Local().Format("2006-01-02"))
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Printf("\n%d node(s) signed, %d unsigned\n", st.Signed, st.Unsigned)
	if st.Unsigned > 0 {
		fmt.Print("\nsign the rest before enabling, or they will be rejected by the whole mesh:\n")
		fmt.Print("  makima-server lock sign\n")
	} else if !st.Enabled {
		fmt.Print("\nevery node is signed. enable enforcement with:\n  makima-server lock enable\n")
	}
	return nil
}

// lockInit generates a signing key and trusts it.
//
// The private half is written locally and never sent. What goes to the server
// is the public half, which is all it needs to record and hand to nodes.
func lockInit(args []string) error {
	af := newAdminFlags("lock init")
	keyPath := af.fs.String("key", DefaultSigningKeyPath(), "where to write the signing key")
	name := af.fs.String("name", "", "a label for this key (defaults to the hostname)")
	force := af.fs.Bool("force", false, "overwrite an existing signing key")

	t, err := af.open(args)
	if err != nil {
		return err
	}

	if _, err := os.Stat(*keyPath); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass -force to replace it, which invalidates every signature it made", *keyPath)
	}
	if st, err := t.lockStatus(); err != nil {
		return err
	} else if len(st.TrustedKeys) > 0 {
		return fmt.Errorf("this network already has a lock. trusting another key is a change to it, signed by a key it already trusts:\n  makima-server lock add-key -public <key> -name <label>")
	}

	if *name == "" {
		if h, err := os.Hostname(); err == nil {
			*name = h
		} else {
			*name = "signing key"
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}

	if err := writeSigningKey(*keyPath, &signingKeyFile{Name: *name, Private: priv, Public: pub}); err != nil {
		return err
	}

	// The lock's first version, signed by the key it trusts.
	first := control.SignLockStatement(priv, 1, false, [][]byte{pub})
	if err := t.applyLock(first, map[string]string{(control.SigningKey{Public: pub}).ID(): *name}); err != nil {
		return err
	}

	fmt.Printf("signing key written to %s\n", *keyPath)
	fmt.Printf("public  %s\n\n", base64.RawURLEncoding.EncodeToString(pub))
	fmt.Print("back that file up. it is not stored on the control server, by design —\n")
	fmt.Print("that is the whole reason a compromised server cannot forge a node.\n\n")
	fmt.Print("next:\n  makima-server lock sign     sign the nodes already registered\n")
	fmt.Print("  makima-server lock enable   start enforcing\n")
	return nil
}

func lockAddKey(args []string) error {
	af := newAdminFlags("lock add-key")
	pubkey := af.fs.String("public", "", "base64url public key to trust")
	name := af.fs.String("name", "", "a label for it")
	keyPath := af.fs.String("key", DefaultSigningKeyPath(), "a signing key the lock already trusts, to sign the change")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *pubkey == "" {
		return fmt.Errorf("lock add-key needs -public")
	}

	pub, err := base64.RawURLEncoding.DecodeString(*pubkey)
	if err != nil {
		return fmt.Errorf("parse -public: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("signing key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}

	names := map[string]string{(control.SigningKey{Public: pub}).ID(): *name}
	err = t.changeLock(*keyPath, names, func(keys [][]byte, enabled bool) ([][]byte, bool, error) {
		if containsKey(keys, pub) {
			return nil, false, fmt.Errorf("that signing key is already trusted")
		}
		return append(keys, pub), enabled, nil
	})
	if err != nil {
		return err
	}
	fmt.Print("trusted\n")
	return nil
}

func lockRemoveKey(args []string) error {
	af := newAdminFlags("lock rm-key")
	id := af.fs.String("id", "", "the key's id, from 'lock status'")
	keyPath := af.fs.String("key", DefaultSigningKeyPath(), "a signing key the lock trusts now, to sign the change")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("lock rm-key needs -id")
	}

	err = t.changeLock(*keyPath, nil, func(keys [][]byte, enabled bool) ([][]byte, bool, error) {
		kept := keys[:0:0]
		for _, k := range keys {
			if (control.SigningKey{Public: k}).ID() != *id {
				kept = append(kept, k)
			}
		}
		if len(kept) == len(keys) {
			return nil, false, fmt.Errorf("no trusted signing key with id %q", *id)
		}
		if len(kept) == 0 && enabled {
			return nil, false, fmt.Errorf("that is the only trusted key and the lock is enabled; disable the lock first, or the mesh would reject every node")
		}
		return kept, enabled, nil
	})
	if err != nil {
		return err
	}
	fmt.Print("removed\n")
	return nil
}

// lockSeal signs a lock set up before versions were signed, as it stands, so
// nodes can hold the server to it from here on.
func lockSeal(args []string) error {
	af := newAdminFlags("lock seal")
	keyPath := af.fs.String("key", DefaultSigningKeyPath(), "a signing key the lock trusts")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	st, err := t.lockStatus()
	if err != nil {
		return err
	}
	if st.Epoch > 0 {
		fmt.Printf("the lock is already signed, at version %d\n", st.Epoch)
		return nil
	}
	if err := t.changeLock(*keyPath, nil, func(keys [][]byte, enabled bool) ([][]byte, bool, error) {
		return keys, enabled, nil
	}); err != nil {
		return err
	}
	fmt.Print("sealed: every node now holds this server to the lock as it stands\n")
	return nil
}

// lockForget throws the lock away, for when every key that could sign a
// change to it is lost.
func lockForget(args []string) error {
	af := newAdminFlags("lock forget")
	t, err := af.open(args)
	if err != nil {
		return err
	}
	if t.live() {
		err = t.admin.ForgetLock()
	} else {
		err = t.store.ForgetLock()
	}
	if err != nil {
		return err
	}
	fmt.Print("the lock is gone from this server, and every node signature with it.\n\n")
	fmt.Print("every machine that held the lock still enforces it — the server cannot tell it\n")
	fmt.Print("otherwise, which is what the lock is for. on each one, as root:\n")
	fmt.Print("  makima lock reset\n")
	return nil
}

// changeLock signs and applies the lock's next version: the current one,
// changed by edit, signed with the key at keyPath — which the current
// version has to trust, since that is what every node will check.
func (t *target) changeLock(keyPath string, names map[string]string, edit func(keys [][]byte, enabled bool) ([][]byte, bool, error)) error {
	sk, err := readSigningKey(keyPath)
	if err != nil {
		return err
	}
	st, err := t.lockStatus()
	if err != nil {
		return err
	}
	if len(st.TrustedKeys) == 0 {
		return fmt.Errorf("network lock is not set up; start one with 'makima-server lock init'")
	}
	var keys [][]byte
	for _, k := range st.TrustedKeys {
		keys = append(keys, k.Public)
	}
	if !containsKey(keys, sk.Public) {
		return fmt.Errorf("the signing key in %s is not one the lock trusts, so no node would accept a change signed with it", keyPath)
	}
	keys, enabled, err := edit(keys, st.Enabled)
	if err != nil {
		return err
	}
	next := control.SignLockStatement(ed25519.PrivateKey(sk.Private), st.Epoch+1, enabled, keys)
	return t.applyLock(next, names)
}

func (t *target) lockStatus() (control.LockStatus, error) {
	if t.live() {
		return t.admin.LockStatus()
	}
	return t.store.LockStatus(), nil
}

func (t *target) applyLock(st control.LockStatement, names map[string]string) error {
	if t.live() {
		return t.admin.ApplyLockStatement(st, names)
	}
	return t.store.ApplyLockStatement(st, names)
}

func containsKey(keys [][]byte, k []byte) bool {
	for _, x := range keys {
		if string(x) == string(k) {
			return true
		}
	}
	return false
}

// lockSign signs every node that needs it.
//
// The server hands over the exact bytes to sign rather than the fields to
// reconstruct them from. Two implementations of "what does a signature cover"
// that drift apart would produce signatures verifying nowhere, and the failure
// would look like a key problem rather than an encoding one.
func lockSign(args []string) error {
	af := newAdminFlags("lock sign")
	keyPath := af.fs.String("key", DefaultSigningKeyPath(), "path to the signing key")

	t, err := af.open(args)
	if err != nil {
		return err
	}

	sk, err := readSigningKey(*keyPath)
	if err != nil {
		return err
	}

	var pending []control.UnsignedNode
	if t.live() {
		pending, err = t.admin.PendingSignatures()
	} else {
		pending = t.store.PendingSignatures()
	}
	if err != nil {
		return err
	}

	if len(pending) == 0 {
		fmt.Print("every node is already signed\n")
		return nil
	}

	for _, n := range pending {
		sig := ed25519.Sign(ed25519.PrivateKey(sk.Private), n.Material)

		if t.live() {
			err = t.admin.ApplySignature(n.ID, sig)
		} else {
			err = t.store.ApplySignature(n.ID, sig)
		}
		if err != nil {
			return fmt.Errorf("sign %s: %w", n.Name, err)
		}
		fmt.Printf("signed %s (node %d)\n", n.Name, n.ID)
	}

	fmt.Printf("\n%d node(s) signed\n", len(pending))
	return nil
}

func lockEnable(args []string, on bool) error {
	af := newAdminFlags("lock enable")
	keyPath := af.fs.String("key", DefaultSigningKeyPath(), "a signing key the lock trusts, to sign the change")
	t, err := af.open(args)
	if err != nil {
		return err
	}

	err = t.changeLock(*keyPath, nil, func(keys [][]byte, enabled bool) ([][]byte, bool, error) {
		return keys, on, nil
	})
	if err != nil {
		return err
	}

	if on {
		fmt.Print("network lock enabled\n\n")
		fmt.Print("every node now verifies its peers' key signatures itself.\n")
		fmt.Print("this control server can no longer introduce a node to the mesh.\n")
		return nil
	}
	fmt.Print("network lock disabled; nodes accept whatever peers the server sends\n")
	fmt.Print("until a version signed by a trusted key enables it again\n")
	return nil
}

// writeSigningKey persists the operator's key.
//
// Mode 0600, write-then-rename, and a directory created 0700 — the same
// treatment every other private key in makima gets, because losing this one
// means losing the ability to admit any new node until a new key is trusted
// and every existing node re-signed.
func writeSigningKey(path string, k *signingKeyFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create signing key dir: %w", err)
	}

	b, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".makima-signing-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readSigningKey(path string) (*signingKeyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no signing key at %s; create one with 'makima-server lock init'", path)
		}
		return nil, err
	}

	var k signingKeyFile
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(k.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: signing key is %d bytes, want %d", path, len(k.Private), ed25519.PrivateKeySize)
	}
	return &k, nil
}
