package sshd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"golang.org/x/crypto/ssh"
)

// keyForTest is a machine key to derive a host key from.
func keyForTest(t *testing.T) (key.Private, error) {
	t.Helper()
	return key.NewPrivate()
}

// fakeAccounts is a machine's password database, without a machine.
type fakeAccounts struct {
	users map[string]*SessionUser
	keys  map[string][]AuthorizedKey
	err   error
}

func (f *fakeAccounts) Lookup(name string) (*SessionUser, error) {
	if u, ok := f.users[name]; ok {
		return u, nil
	}
	return nil, fmt.Errorf("no local account %q", name)
}

func (f *fakeAccounts) List() ([]*SessionUser, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]*SessionUser, 0, len(f.users))
	for _, u := range f.users {
		out = append(out, u)
	}
	return out, nil
}

func (f *fakeAccounts) Keys(u *SessionUser) ([]AuthorizedKey, error) {
	return f.keys[u.Name], nil
}

// pubOf is one fresh public key.
func pubOf(t *testing.T) ssh.PublicKey {
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

// twoAccountServer is a server whose default account is "owner" and which also
// knows "root" and "someone-else".
func twoAccountServer(t *testing.T, ownerKey, rootKey ssh.PublicKey) (*Server, Config) {
	t.Helper()

	owner := &SessionUser{Name: "owner", UID: 501, GID: 20, Home: t.TempDir(), Shell: "/bin/sh"}
	root := &SessionUser{Name: "root", UID: 0, GID: 0, Home: t.TempDir(), Shell: "/bin/sh"}
	other := &SessionUser{Name: "someone-else", UID: 502, GID: 20, Home: t.TempDir(), Shell: "/bin/sh"}

	cfg := Config{
		User: owner,
		Authorized: func(pub ssh.PublicKey, _ netip.Addr) (Grant, bool) {
			ok := string(pub.Marshal()) == string(ownerKey.Marshal())
			return Grant{PTY: ok}, ok
		},
		Accounts: &fakeAccounts{
			users: map[string]*SessionUser{"owner": owner, "root": root, "someone-else": other},
			keys: map[string][]AuthorizedKey{
				"root": {{Key: rootKey, PTY: true}},
			},
		},
	}
	return New(quiet()), cfg
}

// The whole point of the feature, and the whole risk in it: the username is a
// request, and it is granted only by the named account's own authorized_keys.
func TestAnAccountIsOpenedOnlyByItsOwnKeys(t *testing.T) {
	ownerKey, rootKey := pubOf(t), pubOf(t)
	s, cfg := twoAccountServer(t, ownerKey, rootKey)
	from := netip.MustParseAddr("10.77.0.5")

	cases := []struct {
		name, account string
		key           ssh.PublicKey
		want          string // the account a session would run as, "" for refused
	}{
		{"owner key, no username", "", ownerKey, "owner"},
		{"owner key, owner named", "owner", ownerKey, "owner"},
		{"root key, root named", "root", rootKey, "root"},

		// The two that must never work.
		{"owner key asking for root", "root", ownerKey, ""},
		{"root key asking for owner", "owner", rootKey, ""},

		{"root key, no username", "", rootKey, ""},
		{"owner key for an account with no keys", "someone-else", ownerKey, ""},
		{"a key nobody authorized", "owner", pubOf(t), ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			perms, err := s.authorize(cfg, c.account, c.key, from)
			if c.want == "" {
				if err == nil {
					t.Fatalf("allowed in as %q", perms.Extensions[accountExtension])
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got := perms.Extensions[accountExtension]; got != c.want {
				t.Errorf("would run as %q, want %q", got, c.want)
			}
		})
	}
}

// Every ssh client sends the name of whoever is sitting at it, which is rarely
// an account on the far machine. That has always landed on the default
// account, and must keep doing so.
func TestAUsernameThatIsNotAnAccountHereGetsTheDefault(t *testing.T) {
	ownerKey, rootKey := pubOf(t), pubOf(t)
	s, cfg := twoAccountServer(t, ownerKey, rootKey)
	from := netip.MustParseAddr("10.77.0.5")

	perms, err := s.authorize(cfg, "huiyunlee", ownerKey, from)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if got := perms.Extensions[accountExtension]; got != "owner" {
		t.Errorf("ran as %q, want the default account", got)
	}

	// But a key that opens only root does not become the default that way.
	if _, err := s.authorize(cfg, "huiyunlee", rootKey, from); err == nil {
		t.Error("root's key was let in as the default account")
	}
}

// A server with no account source is the server as it was: one account, and
// the username ignored.
func TestWithoutAnAccountSourceEveryLoginIsTheDefault(t *testing.T) {
	ownerKey := pubOf(t)
	s, cfg := twoAccountServer(t, ownerKey, pubOf(t))
	cfg.Accounts = nil
	from := netip.MustParseAddr("10.77.0.5")

	for _, name := range []string{"", "owner", "root", "anybody"} {
		perms, err := s.authorize(cfg, name, ownerKey, from)
		if err != nil {
			t.Fatalf("username %q was refused: %v", name, err)
		}
		if got := perms.Extensions[accountExtension]; got != "owner" {
			t.Errorf("username %q ran as %q, want owner", name, got)
		}
	}
}

func TestListingNamesOnlyTheAccountsAKeyOpens(t *testing.T) {
	ownerKey, rootKey := pubOf(t), pubOf(t)
	s, cfg := twoAccountServer(t, ownerKey, rootKey)
	from := netip.MustParseAddr("10.77.0.5")

	// A key that opens both.
	both := cfg.Accounts.(*fakeAccounts)
	both.keys["root"] = append(both.keys["root"], AuthorizedKey{Key: ownerKey, PTY: true})

	perms, err := s.authorize(cfg, ListAccountsUser, ownerKey, from)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeAccounts(perms.Extensions[listingExtension])
	if len(got) != 2 || got[0].Name != "owner" || !got[0].Default || got[1].Name != "root" || !got[1].Root {
		t.Fatalf("listed %+v, want owner (default) then root", got)
	}

	// A key that opens only root sees only root.
	perms, err = s.authorize(cfg, ListAccountsUser, rootKey, from)
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeAccounts(perms.Extensions[listingExtension]); len(got) != 1 || got[0].Name != "root" {
		t.Fatalf("listed %+v, want root alone", got)
	}

	// A key that opens nothing is refused outright, rather than told so.
	if _, err := s.authorize(cfg, ListAccountsUser, pubOf(t), from); err == nil {
		t.Error("a key that opens nothing was given a listing")
	}
}

// The listing is JSON on the wire, and the client end has to be able to read
// what the server end writes.
func TestTheListingRoundTripsAsJSON(t *testing.T) {
	in := AccountList{Accounts: []Account{
		{Name: "owner", Default: true},
		{Name: "root", Root: true},
	}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out AccountList
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Accounts) != 2 || !out.Accounts[0].Default || !out.Accounts[1].Root {
		t.Errorf("came back as %+v", out.Accounts)
	}
}

func TestAccountOrderPutsRootLast(t *testing.T) {
	got := SortAccounts([]Account{
		{Name: "root", Root: true},
		{Name: "zoe"},
		{Name: "alice"},
		{Name: "owner", Default: true},
	})
	var names []string
	for _, a := range got {
		names = append(names, a.Name)
	}
	if want := "owner,alice,zoe,root"; strings.Join(names, ",") != want {
		t.Errorf("order is %s, want %s", strings.Join(names, ","), want)
	}
}

func TestAccountsWithNoLoginShellAreNotAccounts(t *testing.T) {
	for _, shell := range []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""} {
		if canLogIn(shell) {
			t.Errorf("%q was treated as a login shell", shell)
		}
	}
	for _, shell := range []string{"/bin/sh", "/bin/bash", "/usr/bin/zsh", "/opt/homebrew/bin/fish"} {
		if !canLogIn(shell) {
			t.Errorf("%q was not treated as a login shell", shell)
		}
	}
}

// StrictModes, and the reason for it: a key file anybody can write is a list
// of who may become this account that anybody may add themselves to.
func TestKeysAreIgnoredWhenAnybodyCouldHaveWrittenThem(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	uid, _ := strconv.Atoi(me.Uid)

	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "authorized_keys")
	key := pubOf(t)
	if err := os.WriteFile(file, ssh.MarshalAuthorizedKey(key), 0o600); err != nil {
		t.Fatal(err)
	}

	u := &SessionUser{Name: me.Username, UID: uid, Home: home, Shell: "/bin/sh"}
	keys, err := (SystemAccounts{}).Keys(u)
	if err != nil {
		t.Fatalf("a correctly-owned file was refused: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("read %d keys, want 1", len(keys))
	}

	// World-writable: refused.
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if keys, _ := (SystemAccounts{}).Keys(u); len(keys) != 0 {
		t.Error("a world-writable authorized_keys was honoured")
	}

	// A world-writable .ssh is the same hole one step removed.
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if keys, _ := (SystemAccounts{}).Keys(u); len(keys) != 0 {
		t.Error("keys under a world-writable .ssh were honoured")
	}
}

// A missing .ssh is an account with no keys, not an error worth reporting.
func TestAnAccountWithNoSSHDirectoryHasNoKeys(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	uid, _ := strconv.Atoi(me.Uid)

	u := &SessionUser{Name: me.Username, UID: uid, Home: t.TempDir(), Shell: "/bin/sh"}
	keys, err := (SystemAccounts{}).Keys(u)
	if err != nil {
		t.Errorf("reported an error for an account with no .ssh: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("found %d keys where there is no .ssh", len(keys))
	}
}

// This machine's own accounts, whatever they are, must at least resolve.
func TestTheCurrentAccountResolves(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	u, err := (SystemAccounts{}).Lookup(me.Username)
	if err != nil {
		t.Skipf("this account is not one sessions can run as: %v", err)
	}
	if u.Name != me.Username || u.Home != me.HomeDir {
		t.Errorf("resolved to %+v, want %s at %s", u, me.Username, me.HomeDir)
	}
	if u.Shell == "" {
		t.Error("no login shell was found")
	}
	if len(u.Groups) == 0 {
		t.Error("no supplementary groups were found, so a session would have none")
	}
}

func TestListingAccountsFindsThisOne(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	users, err := (SystemAccounts{}).List()
	if err != nil {
		t.Skipf("accounts cannot be listed here: %v", err)
	}
	for _, u := range users {
		if u.Name == me.Username {
			return
		}
	}
	t.Errorf("the account running the tests (%s) was not in the list of %d", me.Username, len(users))
}

// Everything above tests the decision. This tests the wire: a real client, a
// real handshake, and a session that really runs as the account it asked for.
func multiAccountServer(t *testing.T, ownerKey, altKey ssh.PublicKey) (string, ssh.Signer) {
	t.Helper()

	mk, err := keyForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	host, err := HostKey(mk)
	if err != nil {
		t.Fatal(err)
	}

	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(me.Uid)
	gid, _ := strconv.Atoi(me.Gid)

	// Both accounts are this one, under two names. The test cannot make a
	// second real account, and what is being tested is which name the server
	// picks — the dropping of privileges to it needs root and a machine, and
	// is the one part only a real deployment exercises.
	owner := &SessionUser{Name: me.Username, UID: uid, GID: gid, Home: me.HomeDir, Shell: "/bin/sh"}
	alt := &SessionUser{Name: "alt", UID: uid, GID: gid, Home: me.HomeDir, Shell: "/bin/sh"}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()

	s := New(quiet())
	t.Cleanup(s.Close)

	err = s.Apply(Config{
		Addr:    netip.MustParseAddr("127.0.0.1"),
		Port:    port,
		HostKey: host,
		Authorized: func(pub ssh.PublicKey, _ netip.Addr) (Grant, bool) {
			ok := string(pub.Marshal()) == string(ownerKey.Marshal())
			return Grant{PTY: ok}, ok
		},
		Accounts: &fakeAccounts{
			users: map[string]*SessionUser{me.Username: owner, "alt": alt},
			keys:  map[string][]AuthorizedKey{"alt": {{Key: altKey, PTY: true}}},
		},
		User:   owner,
		Logger: quiet(),
	})
	if err != nil {
		t.Skipf("could not start the ssh server here: %v", err)
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), host
}

func dialAs(t *testing.T, addr, account string, signer, host ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            account,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(host.PublicKey()),
		Timeout:         10 * time.Second,
	})
}

func TestASessionRunsAsTheAccountItAskedFor(t *testing.T) {
	ownerSigner, altSigner := clientKey(t), clientKey(t)
	addr, host := multiAccountServer(t, ownerSigner.PublicKey(), altSigner.PublicKey())

	// alt's key opens alt.
	c, err := dialAs(t, addr, "alt", altSigner, host)
	if err != nil {
		t.Fatalf("alt's key was refused for alt: %v", err)
	}
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("echo $USER")
	sess.Close()
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "alt" {
		t.Errorf("the session ran as %q, want alt", got)
	}

	// The owner's key does not.
	if c, err := dialAs(t, addr, "alt", ownerSigner, host); err == nil {
		c.Close()
		t.Error("the owner's key opened alt")
	}

	// And alt's key does not open the owner's account.
	me, _ := user.Current()
	if c, err := dialAs(t, addr, me.Username, altSigner, host); err == nil {
		c.Close()
		t.Error("alt's key opened the owner's account")
	}
}

func TestTheAccountListingComesBackOverARealConnection(t *testing.T) {
	ownerSigner, altSigner := clientKey(t), clientKey(t)
	addr, host := multiAccountServer(t, ownerSigner.PublicKey(), altSigner.PublicKey())

	c, err := dialAs(t, addr, ListAccountsUser, altSigner, host)
	if err != nil {
		t.Fatalf("the listing username was refused: %v", err)
	}
	defer c.Close()

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	out, err := sess.Output("anything at all")
	if err != nil {
		t.Fatal(err)
	}

	var list AccountList
	if err := json.Unmarshal(out, &list); err != nil {
		t.Fatalf("the listing was not JSON: %v (%q)", err, out)
	}
	if len(list.Accounts) != 1 || list.Accounts[0].Name != "alt" {
		t.Errorf("listed %+v, want alt alone", list.Accounts)
	}
}

// The listing username answers one question and hands out no shell.
func TestTheListingUsernameCannotRunAnything(t *testing.T) {
	ownerSigner, altSigner := clientKey(t), clientKey(t)
	addr, host := multiAccountServer(t, ownerSigner.PublicKey(), altSigner.PublicKey())

	c, err := dialAs(t, addr, ListAccountsUser, altSigner, host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Error("the listing username was given a terminal")
	}

	out, err := sess.Output("id -un")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "uid=") || !strings.Contains(string(out), "accounts") {
		t.Errorf("a command ran instead of the listing being returned: %q", out)
	}
}
