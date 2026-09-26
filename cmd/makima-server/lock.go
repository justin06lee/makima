package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"golang.org/x/term"
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

	// Networks is, for each network whose lock this key has changed — by its
	// control plane's key — the version it last signed there. A node keeps
	// the lock it has accepted so the server cannot tell it otherwise; this
	// is the same for the signing side, so the server cannot get this key to
	// sign a change to a lock it has quietly rewritten.
	Networks map[string]*netmap.LockPin `json:"networks,omitempty"`
}

// remember records next as the version this key last signed in network, so
// the next change starts from it. A key file that cannot be written is only
// warned about: the version is already on the server.
func (sk *signingKeyFile) remember(path string, network key.Public, next control.LockStatement) {
	if sk.Networks == nil {
		sk.Networks = map[string]*netmap.LockPin{}
	}
	sk.Networks[network.String()] = &netmap.LockPin{Epoch: next.Epoch, Enabled: next.Enabled, Keys: next.Keys}
	if err := writeSigningKey(path, sk); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record lock version %d in %s: %v\n", next.Epoch, path, err)
	}
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
		if st.Enabled {
			fmt.Print("\nthe unsigned ones have no signature naming this network — none at all, or one\n")
			fmt.Print("made by makima v0.3.0 — and a node holding a signed lock will not take them:\n")
		} else {
			fmt.Print("\nsign the rest before enabling, or they will be rejected by the whole mesh:\n")
		}
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

	sk := &signingKeyFile{Name: *name, Private: priv, Public: pub}
	if err := writeSigningKey(*keyPath, sk); err != nil {
		return err
	}

	// The lock's first version, signed by the key it trusts.
	network, err := t.serverKey()
	if err != nil {
		return err
	}
	first := control.SignLockStatement(priv, network, 1, false, [][]byte{pub})
	if err := t.applyLock(first, map[string]string{(control.SigningKey{Public: pub}).ID(): *name}); err != nil {
		return err
	}
	sk.remember(*keyPath, network, first)

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
	yes := af.fs.Bool("yes", false, "sign the machines only the dropped key had signed without asking")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("lock rm-key needs -id")
	}

	// The machines only the dropped key had signed are signed again first,
	// with the key making the change. Otherwise an enforced lock could not
	// drop it — the version would have them rejected by the whole mesh —
	// and nothing else would sign them while the old key still counts.
	sk, err := readSigningKey(*keyPath)
	if err != nil {
		return err
	}
	if (control.SigningKey{Public: sk.Public}).ID() == *id {
		return fmt.Errorf("that is the key in %s, signing this change; sign dropping it with a key that stays", *keyPath)
	}
	if _, cur, err := t.currentLock(sk); err != nil {
		return err
	} else if !containsKey(cur.Keys, sk.Public) {
		return fmt.Errorf("the signing key in %s is not one the lock trusts, so no node would accept a change signed with it", *keyPath)
	}
	if n, err := t.signPendingWithout(sk, *yes, *id); err != nil {
		return err
	} else if n > 0 {
		fmt.Print("\n")
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
		if len(kept) == 0 {
			// Nothing could sign the version after one that trusts no key.
			return nil, false, fmt.Errorf("that is the only trusted key; trust another first (lock add-key), or start the lock over (lock forget)")
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
	yes := af.fs.Bool("yes", false, "pin the keys and sign the machines without asking")

	t, err := af.open(args)
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
	if st.Epoch > 0 {
		fmt.Printf("the lock is already signed, at version %d\n", st.Epoch)
		return nil
	}
	sk, err := readSigningKey(*keyPath)
	if err != nil {
		return err
	}
	var keys [][]byte
	for _, k := range st.TrustedKeys {
		keys = append(keys, k.Public)
	}
	if !containsKey(keys, sk.Public) {
		return fmt.Errorf("the signing key in %s is not one the lock trusts, so no node would accept a version signed with it", *keyPath)
	}

	// A lock that was never signed has no history to check what it trusts
	// against: the server's word is all there is, and sealing pins it on
	// every node for good. So it is shown first.
	if !*yes {
		ok, err := confirmSeal(st.TrustedKeys)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("not sealed")
		}
	}

	// A node holding a signed lock takes only signatures that name this
	// network, and a lock from before versions were signed has nodes signed
	// the older way. So an enforced one has them signed again first; it
	// could not be sealed otherwise, since every node would be rejected. One
	// not enforced yet can wait for 'lock sign' before 'lock enable'.
	if st.Enabled {
		if n, err := t.signPending(sk, *yes); err != nil {
			return err
		} else if n > 0 {
			fmt.Print("\n")
		}
	}

	network, err := t.serverKey()
	if err != nil {
		return err
	}
	first := control.SignLockStatement(ed25519.PrivateKey(sk.Private), network, 1, st.Enabled, keys)
	if err := t.applyLock(first, nil); err != nil {
		return err
	}
	sk.remember(*keyPath, network, first)
	fmt.Print("sealed: every node now holds this server to the lock as it stands\n")
	return nil
}

// confirmSeal shows the keys a lock that was never signed is about to be
// pinned to, and asks. A variable so tests can answer.
var confirmSeal = func(keys []control.SigningKey) (bool, error) {
	fmt.Print("this lock was never signed, so which keys it trusts is the server's word.\n")
	fmt.Print("sealing pins these on every node:\n\n")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprint(w, "ID\tNAME\n")
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%s\n", k.ID(), k.Name)
	}
	if err := w.Flush(); err != nil {
		return false, err
	}
	return ask("\nare these all yours? [y/N] ")
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
	fmt.Print("the lock is gone from this server. node signatures are kept, since machines that\n")
	fmt.Print("still hold the lock check their peers against them.\n\n")
	fmt.Print("every machine that held the lock still enforces it — the server cannot tell it\n")
	fmt.Print("otherwise, which is what the lock is for. on each one, as root:\n")
	fmt.Print("  makima lock reset\n")
	return nil
}

// changeLock signs and applies the lock's next version: the current one,
// changed by edit, signed with the key at keyPath — which the current
// version has to trust, since that is what every node will check.
//
// Where the lock stands is read from its signed versions, not from what the
// server says about them. The server is what the lock defends against, and
// building on its word let a compromised one report a key of its own among
// the trusted and have the operator's next change sign it in — every node
// would take that version, since the operator's key signed it. The versions
// are followed from the one this key last signed here, as a node follows them
// from its pin, so a history the server rewrote gets nothing signed.
func (t *target) changeLock(keyPath string, names map[string]string, edit func(keys [][]byte, enabled bool) ([][]byte, bool, error)) error {
	sk, err := readSigningKey(keyPath)
	if err != nil {
		return err
	}
	network, cur, err := t.currentLock(sk)
	if err != nil {
		return err
	}
	if !containsKey(cur.Keys, sk.Public) {
		return fmt.Errorf("the signing key in %s is not one the lock trusts, so no node would accept a change signed with it", keyPath)
	}
	keys, enabled, err := edit(cur.Keys, cur.Enabled)
	if err != nil {
		return err
	}
	next := control.SignLockStatement(ed25519.PrivateKey(sk.Private), network, cur.Epoch+1, enabled, keys)
	if err := t.applyLock(next, names); err != nil {
		return err
	}
	sk.remember(keyPath, network, next)
	return nil
}

// currentLock is the lock as its signed versions leave it, followed from the
// version sk last signed in this network — or, the first time sk changes it,
// from the beginning, as a node that has never seen the lock would.
func (t *target) currentLock(sk *signingKeyFile) (key.Public, *netmap.LockPin, error) {
	network, err := t.serverKey()
	if err != nil {
		return key.Public{}, nil, err
	}
	chain, err := t.lockChain()
	if err != nil {
		return key.Public{}, nil, err
	}
	if len(chain) == 0 {
		st, err := t.lockStatus()
		if err != nil {
			return key.Public{}, nil, err
		}
		if len(st.TrustedKeys) == 0 {
			return key.Public{}, nil, fmt.Errorf("network lock is not set up; start one with 'makima-server lock init'")
		}
		return key.Public{}, nil, fmt.Errorf("this lock was set up by an older makima and has no signed history to change; seal it first:\n  makima-server lock seal")
	}

	pin := sk.Networks[network.String()]
	cur, err := control.AdvanceLock(network, pin, chain)
	if err != nil {
		return key.Public{}, nil, fmt.Errorf("the lock this server holds does not follow, by signed versions, from the one this key last signed here — nothing was signed: %w", err)
	}
	if last := chain[len(chain)-1].Epoch; cur == nil || last != cur.Epoch {
		return key.Public{}, nil, fmt.Errorf("the server's lock is at version %d, but this key last signed version %d here; it has lost or hidden versions — nothing was signed", last, pinEpoch(cur))
	}
	return network, cur, nil
}

func pinEpoch(p *netmap.LockPin) uint64 {
	if p == nil {
		return 0
	}
	return p.Epoch
}

func (t *target) lockChain() ([]control.LockStatement, error) {
	if t.live() {
		return t.admin.LockChain()
	}
	return t.store.LockChain(), nil
}

func (t *target) lockStatus() (control.LockStatus, error) {
	if t.live() {
		return t.admin.LockStatus()
	}
	return t.store.LockStatus(), nil
}

// serverKey is the control plane's public key: the network every version of
// its lock is signed for, so the same signing key's versions for another
// network are refused by this one's nodes.
func (t *target) serverKey() (key.Public, error) {
	if t.live() {
		return t.admin.ServerKey()
	}
	return t.store.ServerKey().Public(), nil
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
	yes := af.fs.Bool("yes", false, "sign machines this key has never signed without asking")

	t, err := af.open(args)
	if err != nil {
		return err
	}

	sk, err := readSigningKey(*keyPath)
	if err != nil {
		return err
	}

	n, err := t.signPending(sk, *yes)
	if err != nil {
		return err
	}
	if n == 0 {
		fmt.Print("every node is already signed\n")
		return nil
	}
	fmt.Printf("\n%d node(s) signed\n", n)
	return nil
}

// signPending signs every node the server says needs it — no signature, one
// from a key no longer trusted, or one from makima v0.3.0, which names no
// network — and reports how many it signed.
//
// The list is the server's, and the server is what the lock defends against.
// Signing whatever it named let a compromised one register a machine of its
// own and wait for the next routine `lock sign`, with nothing to forge. So
// every machine is shown, and signed only once somebody agrees — at the
// terminal, or with yes — and the bytes are checked to be exactly each named
// machine's, in the network of the server being talked to. That network's key
// comes from the server too; what the check catches is a server asking for a
// key other than the machine it names, or for one network while claiming to
// be another only if it slips.
//
// None goes through unasked, not even one this key signed under makima
// v0.3.0: a server can keep an old signature — for a machine since forgotten,
// or from another network sharing the key — and present it as proof of a
// machine it made up.
func (t *target) signPending(sk *signingKeyFile, yes bool) (int, error) {
	return t.signPendingWithout(sk, yes, "")
}

// signPendingWithout is signPending as things will be once the trusted key
// with ID without is dropped: the machines only it had signed are signed too.
func (t *target) signPendingWithout(sk *signingKeyFile, yes bool, without string) (int, error) {
	var (
		pending []control.UnsignedNode
		err     error
	)
	if t.live() {
		pending, err = t.admin.PendingSignaturesWithout(without)
	} else {
		pending = t.store.PendingSignaturesWithout(without)
	}
	if err != nil {
		return 0, err
	}
	network, err := t.serverKey()
	if err != nil {
		return 0, err
	}

	if len(pending) == 0 {
		return 0, nil
	}
	for _, n := range pending {
		if bytes.Equal(n.Material, control.LegacySigningMaterial(n.ID, n.NodeKey)) {
			return 0, errors.New("the running server is an older makima, which asks for signatures that name no network; restart it on this version (it restarts itself after an update), then sign again")
		}
		if !bytes.Equal(n.Material, control.SigningMaterial(network, n.ID, n.NodeKey)) {
			return 0, fmt.Errorf("the server asked to sign something other than %s's key in this network; nothing was signed", n.Name)
		}
		if len(n.LegacyMaterial) > 0 && !bytes.Equal(n.LegacyMaterial, control.LegacySigningMaterial(n.ID, n.NodeKey)) {
			return 0, fmt.Errorf("the server asked to sign something other than %s's key; nothing was signed", n.Name)
		}
	}
	if !yes {
		ok, err := confirmSigning(pending)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, errors.New("nothing was signed")
		}
	}

	for _, n := range pending {
		sig := ed25519.Sign(ed25519.PrivateKey(sk.Private), n.Material)
		// The old kind too, for machines still on makima v0.3.0, which
		// check nothing else and would refuse this one otherwise.
		var legacy []byte
		if len(n.LegacyMaterial) > 0 {
			legacy = ed25519.Sign(ed25519.PrivateKey(sk.Private), n.LegacyMaterial)
		}

		if t.live() {
			err = t.admin.ApplySignatures(n.ID, sig, legacy)
		} else {
			err = t.store.ApplySignatures(n.ID, sig, legacy)
		}
		if err != nil {
			return 0, fmt.Errorf("sign %s: %w", n.Name, err)
		}
		fmt.Printf("signed %s (node %d)\n", n.Name, n.ID)
	}
	return len(pending), nil
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

// confirmSigning shows the machines about to be signed and asks whether to
// sign them. A variable so tests can answer.
var confirmSigning = func(fresh []control.UnsignedNode) (bool, error) {
	fmt.Print("to be signed:\n\n")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprint(w, "NAME\tID\tNODE KEY\n")
	for _, n := range fresh {
		k := n.NodeKey.String()
		fmt.Fprintf(w, "%s\t%d\t%s…\n", n.Name, n.ID, k[:16])
	}
	if err := w.Flush(); err != nil {
		return false, err
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Println()
		return false, fmt.Errorf("no terminal to ask at: check each of these is yours ('makima status' on it shows its node key), then run again with -yes")
	}
	fmt.Print("\nthe server chose this list, so a machine you do not recognise may be its own.\n")
	return ask("each machine's 'makima status' shows its node key. sign them? [y/N] ")
}

// ask puts a yes-or-no question to whoever is at the terminal; no terminal
// is an error that says to pass -yes, never a yes.
func ask(question string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, errors.New("no terminal to ask at; check the list above, then run again with -yes")
	}
	fmt.Print(question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
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
