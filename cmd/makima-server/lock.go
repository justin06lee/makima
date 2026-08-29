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
	default:
		return fmt.Errorf("unknown lock subcommand %q (try: status, init, sign, enable, disable, add-key, rm-key)", args[0])
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
	fmt.Printf("network lock: %s\n\n", state)

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

	if t.live() {
		err = t.admin.AddSigningKey(*name, pub)
	} else {
		err = t.store.AddSigningKey(*name, pub)
	}
	if err != nil {
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

	if t.live() {
		err = t.admin.AddSigningKey(*name, pub)
	} else {
		err = t.store.AddSigningKey(*name, pub)
	}
	if err != nil {
		return err
	}
	fmt.Print("trusted\n")
	return nil
}

func lockRemoveKey(args []string) error {
	af := newAdminFlags("lock rm-key")
	id := af.fs.String("id", "", "the key's id, from 'lock status'")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("lock rm-key needs -id")
	}

	if t.live() {
		err = t.admin.RemoveSigningKey(*id)
	} else {
		err = t.store.RemoveSigningKey(*id)
	}
	if err != nil {
		return err
	}
	fmt.Print("removed\n")
	return nil
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
	t, err := af.open(args)
	if err != nil {
		return err
	}

	if t.live() {
		err = t.admin.SetLockEnabled(on)
	} else {
		err = t.store.SetLockEnabled(on)
	}
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
