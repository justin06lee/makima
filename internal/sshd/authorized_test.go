package sshd

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testKey makes one authorized key to hand around.
func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519Keys()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func quietKeys() *Keys { return NewKeys(log.New(io.Discard, "", 0)) }

func TestKeysReadFromAFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "authorized_keys")
	want := testKey(t)
	if err := os.WriteFile(file, ssh.MarshalAuthorizedKey(want), 0o600); err != nil {
		t.Fatal(err)
	}

	k := quietKeys()
	defer k.Close()
	if err := k.Set(context.Background(), []Source{Source(file)}); err != nil {
		t.Fatal(err)
	}

	if !k.Allow(want) {
		t.Error("the key in the file was not allowed")
	}
	if k.Allow(testKey(t)) {
		t.Error("a key that was never in the file was allowed")
	}
	if n, _, err := k.Status(); n != 1 || err != nil {
		t.Errorf("status reported %d keys, err %v; want 1, nil", n, err)
	}
}

func TestNoKeyIsAllowedBeforeAnySourceIsSet(t *testing.T) {
	k := quietKeys()
	defer k.Close()
	if k.Allow(testKey(t)) {
		t.Error("a key was allowed with no sources set")
	}
	if k.Allow(nil) {
		t.Error("a nil key was allowed")
	}
}

// Taking a key out of the file revokes it on the next read.
func TestRemovingAKeyRevokesIt(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "authorized_keys")
	gone, stays := testKey(t), testKey(t)
	both := append(ssh.MarshalAuthorizedKey(gone), ssh.MarshalAuthorizedKey(stays)...)
	if err := os.WriteFile(file, both, 0o600); err != nil {
		t.Fatal(err)
	}

	k := quietKeys()
	defer k.Close()
	if err := k.Set(context.Background(), []Source{Source(file)}); err != nil {
		t.Fatal(err)
	}
	if !k.Allow(gone) || !k.Allow(stays) {
		t.Fatal("both keys should have been allowed")
	}

	if err := os.WriteFile(file, ssh.MarshalAuthorizedKey(stays), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := k.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k.Allow(gone) {
		t.Error("a key taken out of the file is still allowed")
	}
	if !k.Allow(stays) {
		t.Error("a key still in the file was revoked")
	}
}

// A source that cannot be read keeps its keys for a while, and then stops.
// Revocation that only works while the network does is not revocation.
func TestUnreadableSourceKeysExpire(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "authorized_keys")
	pub := testKey(t)
	if err := os.WriteFile(file, ssh.MarshalAuthorizedKey(pub), 0o600); err != nil {
		t.Fatal(err)
	}

	k := quietKeys()
	defer k.Close()
	if err := k.Set(context.Background(), []Source{Source(file)}); err != nil {
		t.Fatal(err)
	}
	if !k.Allow(pub) {
		t.Fatal("the key in the file was not allowed")
	}

	// The source goes away. Its last good read still stands.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := k.refresh(context.Background()); err == nil {
		t.Error("an unreadable source was not reported")
	}
	if !k.Allow(pub) {
		t.Error("a briefly unreadable source revoked its keys")
	}

	// Age that read past the cap, and it stops standing.
	k.mu.Lock()
	for s, c := range k.cached {
		k.cached[s] = cachedKeys{keys: c.keys, at: time.Now().Add(-staleAfter - time.Minute)}
	}
	k.mu.Unlock()

	_ = k.refresh(context.Background())
	if k.Allow(pub) {
		t.Error("a source unreadable for longer than staleAfter still had its keys honoured")
	}
	if n, _, _ := k.Status(); n != 0 {
		t.Errorf("status reported %d keys in force, want 0", n)
	}
}

// One unreachable source must not revoke another's keys.
func TestOneFailingSourceDoesNotRevokeTheOthers(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	pub := testKey(t)
	if err := os.WriteFile(good, ssh.MarshalAuthorizedKey(pub), 0o600); err != nil {
		t.Fatal(err)
	}

	k := quietKeys()
	defer k.Close()
	if err := k.Set(context.Background(), []Source{Source(good), Source(filepath.Join(dir, "missing"))}); err == nil {
		t.Error("a missing source was not reported")
	}
	if !k.Allow(pub) {
		t.Error("a readable source lost its keys because another source failed")
	}
}

func TestParseAuthorizedKeysSkipsCommentsAndBlanks(t *testing.T) {
	a, b := testKey(t), testKey(t)
	file := append([]byte("# a comment\n\n"), ssh.MarshalAuthorizedKey(a)...)
	file = append(file, '\n')
	file = append(file, ssh.MarshalAuthorizedKey(b)...)

	got, err := ParseAuthorizedKeys(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d keys, want 2", len(got))
	}
}

func TestParseAuthorizedKeysRejectsRubbish(t *testing.T) {
	if _, err := ParseAuthorizedKeys([]byte("ssh-ed25519 not-base64 nope\n")); err == nil {
		t.Error("a malformed key file parsed without error")
	}
}
