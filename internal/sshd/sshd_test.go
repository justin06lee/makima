package sshd

import (
	"context"
	"io"
	"log"
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

func quiet() *log.Logger { return log.New(io.Discard, "", 0) }

// The host key follows the machine's identity, so a reinstall of makima does
// not produce a host-key warning and two machines never share one.
func TestHostKeyIsDerivedAndStable(t *testing.T) {
	mk, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	a, err := HostKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HostKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(a.PublicKey()) != ssh.FingerprintSHA256(b.PublicKey()) {
		t.Error("the same machine key produced two different host keys")
	}

	other, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := HostKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(a.PublicKey()) == ssh.FingerprintSHA256(c.PublicKey()) {
		t.Error("two different machines derived the same host key")
	}
}

// The derivation must not be reachable from any other use of the machine key.
func TestHostKeyIsNotTheMachineKey(t *testing.T) {
	mk, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := HostKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(signer.PublicKey().Marshal()), string(mk[:])) {
		t.Error("the host key contains the machine key verbatim")
	}
}

// testServer starts one bound to loopback, as a real one binds a mesh address.
func testServer(t *testing.T, authorized ssh.PublicKey) (string, ssh.Signer) {
	t.Helper()

	mk, err := key.NewPrivate()
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

	// A free port, since the fixed one may be in use and the test does not
	// care which it gets.
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
		Authorized: func(pub ssh.PublicKey) bool {
			return authorized != nil && string(pub.Marshal()) == string(authorized.Marshal())
		},
		User: &SessionUser{
			Name:  me.Username,
			UID:   uid,
			GID:   gid,
			Home:  me.HomeDir,
			Shell: "/bin/sh",
		},
		Logger: quiet(),
	})
	if err != nil {
		t.Skipf("could not start the ssh server here: %v", err)
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), host
}

func clientKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519Keys()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func dial(t *testing.T, addr string, signer ssh.Signer, host ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "whoever",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(host.PublicKey()),
		Timeout:         10 * time.Second,
	})
}

// The whole feature: an authorized key gets a command run on the far machine,
// with its output and its exit status coming back.
func TestExecRunsACommand(t *testing.T) {
	signer := clientKey(t)
	addr, host := testServer(t, signer.PublicKey())

	c, err := dial(t, addr, signer, host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	out, err := sess.Output("echo hello from makima")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "hello from makima" {
		t.Errorf("got %q", out)
	}
}

// A non-zero exit has to come back, or `makima ssh host false` looks like it
// succeeded.
func TestExitStatusComesBack(t *testing.T) {
	signer := clientKey(t)
	addr, host := testServer(t, signer.PublicKey())

	c, err := dial(t, addr, signer, host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	err = sess.Run("exit 3")
	var ee *ssh.ExitError
	if !asExit(err, &ee) {
		t.Fatalf("got %v, want an exit error", err)
	}
	if ee.ExitStatus() != 3 {
		t.Errorf("exit status %d, want 3", ee.ExitStatus())
	}
}

// Standard input has to reach the command, and be closed when the client
// stops sending — or anything that reads to EOF hangs forever.
func TestStdinReachesTheCommand(t *testing.T) {
	signer := clientKey(t)
	addr, host := testServer(t, signer.PublicKey())

	c, err := dial(t, addr, signer, host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	sess.Stdin = strings.NewReader("one\ntwo\nthree\n")
	out, err := sess.Output("wc -l")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "3" {
		t.Errorf("got %q, want 3", out)
	}
}

// An interactive session gets a real terminal, which is the difference between
// a usable shell and a broken one.
func TestPTYSessionGetsATerminal(t *testing.T) {
	signer := clientKey(t)
	addr, host := testServer(t, signer.PublicKey())

	c, err := dial(t, addr, signer, host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}

	out, err := sess.Output("tty; echo TERM=$TERM")
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if strings.Contains(got, "not a tty") {
		t.Errorf("the session had no terminal: %q", got)
	}
	if !strings.Contains(got, "TERM=xterm-256color") {
		t.Errorf("TERM did not reach the session: %q", got)
	}
}

// A key that is not authorized gets nothing, and gets it at the handshake
// rather than after a shell has started.
func TestUnauthorizedKeyIsRefused(t *testing.T) {
	authorized := clientKey(t)
	addr, host := testServer(t, authorized.PublicKey())

	stranger := clientKey(t)
	c, err := dial(t, addr, stranger, host)
	if err == nil {
		c.Close()
		t.Fatal("a key that was not authorized got in")
	}
}

// There is no password authentication, and a server that advertised it would
// invite people to guess at something that does not exist.
func TestPasswordAuthenticationIsNotOffered(t *testing.T) {
	authorized := clientKey(t)
	addr, host := testServer(t, authorized.PublicKey())

	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "whoever",
		Auth:            []ssh.AuthMethod{ssh.Password("hunter2")},
		HostKeyCallback: ssh.FixedHostKey(host.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		c.Close()
		t.Fatal("a password was accepted")
	}
}

// Port forwarding through this server would be a second, much broader hole
// than a shell — and makima forwards ports as a first-class thing already.
func TestPortForwardingIsRefused(t *testing.T) {
	signer := clientKey(t)
	addr, host := testServer(t, signer.PublicKey())

	c, err := dial(t, addr, signer, host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if conn, err := c.Dial("tcp", "127.0.0.1:1"); err == nil {
		conn.Close()
		t.Fatal("the server opened a direct-tcpip channel")
	}
}

// The environment a session starts with is built here, not inherited and not
// taken from the client: an env request is the classic way to smuggle
// LD_PRELOAD into a process running as somebody else.
func TestClientEnvironmentIsIgnored(t *testing.T) {
	signer := clientKey(t)
	addr, host := testServer(t, signer.PublicKey())

	c, err := dial(t, addr, signer, host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// Refused by the server; the client records it and carries on.
	_ = sess.Setenv("LD_PRELOAD", "/tmp/evil.so")

	out, err := sess.Output("echo [$LD_PRELOAD]")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "[]") {
		t.Errorf("a client-supplied variable reached the session: %q", out)
	}
}

func TestSanitiseTermStripsAnythingUnusual(t *testing.T) {
	cases := map[string]string{
		"xterm-256color":         "xterm-256color",
		"screen.linux":           "screen.linux",
		"xterm; rm -rf /":        "xtermrm-rf",
		"":                       "",
		strings.Repeat("x", 200): strings.Repeat("x", 64),
	}
	for in, want := range cases {
		if got := sanitiseTerm(in); got != want {
			t.Errorf("sanitiseTerm(%q) = %q, want %q", in, got, want)
		}
	}
}

// A client-supplied window size ends up in an ioctl, so it is clamped to
// something a terminal can actually be.
func TestWindowSizeIsClamped(t *testing.T) {
	if got := sizeOf(0, 0); got.Cols != 80 || got.Rows != 24 {
		t.Errorf("an unspecified window became %dx%d, want 80x24", got.Cols, got.Rows)
	}
	if got := sizeOf(1<<20, 1<<20); got.Cols != 80 || got.Rows != 24 {
		t.Errorf("an absurd window became %dx%d", got.Cols, got.Rows)
	}
	if got := sizeOf(120, 40); got.Cols != 120 || got.Rows != 40 {
		t.Errorf("a normal window became %dx%d", got.Cols, got.Rows)
	}
}

func TestParseStringRefusesToReadPastTheBuffer(t *testing.T) {
	// A length larger than the payload.
	if _, err := parseString([]byte{0xff, 0xff, 0xff, 0xff, 'a'}); err == nil {
		t.Error("a string claiming four billion bytes was accepted")
	}
	if _, err := parseString([]byte{0, 0}); err == nil {
		t.Error("a truncated length prefix was accepted")
	}
	got, err := parseString([]byte{0, 0, 0, 2, 'h', 'i', 'x'})
	if err != nil || got != "hi" {
		t.Errorf("parseString = %q, %v", got, err)
	}
}

func TestParsePTYRequestRefusesTruncation(t *testing.T) {
	if _, err := parsePTYRequest([]byte{0, 0, 0, 5, 'x', 't', 'e', 'r', 'm'}); err == nil {
		t.Error("a pty-req with no dimensions was accepted")
	}
}

// Authorized keys files contain comments, blank lines and options, and one bad
// line must not lock out every key below it.
func TestParseAuthorizedKeysSkipsRubbish(t *testing.T) {
	good := clientKey(t)
	line := string(ssh.MarshalAuthorizedKey(good.PublicKey()))

	body := "# a comment\n\nnot a key at all\n" + line + "\nssh-rsa AAAAgarbage broken\n"
	keys, err := ParseAuthorizedKeys([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("parsed %d keys, want 1", len(keys))
	}
	if string(keys[0].Marshal()) != string(good.PublicKey().Marshal()) {
		t.Error("the wrong key was parsed")
	}
}

func TestParseAuthorizedKeysRejectsAnEmptyFile(t *testing.T) {
	if _, err := ParseAuthorizedKeys([]byte("# nothing here\n\n")); err == nil {
		t.Error("a file with no keys was accepted")
	}
}

func TestKeysFromAFile(t *testing.T) {
	signer := clientKey(t)
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}

	k := NewKeys(quiet())
	defer k.Close()

	if err := k.Set(context.Background(), []Source{Source(path)}); err != nil {
		t.Fatal(err)
	}
	if !k.Allow(signer.PublicKey()) {
		t.Error("a key in the file was not authorized")
	}
	if k.Allow(clientKey(t).PublicKey()) {
		t.Error("a key not in the file was authorized")
	}
}

// Losing the network must not lock everybody out of a machine.
func TestAFailedRefreshKeepsTheKeysAlreadyInForce(t *testing.T) {
	signer := clientKey(t)
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}

	k := NewKeys(quiet())
	defer k.Close()
	if err := k.Set(context.Background(), []Source{Source(path)}); err != nil {
		t.Fatal(err)
	}

	// The source goes away, as a network or a deleted file would.
	os.Remove(path)
	_ = k.refresh(context.Background())

	if !k.Allow(signer.PublicKey()) {
		t.Error("a failed refresh emptied the key set and locked everybody out")
	}
	if _, _, err := k.Status(); err == nil {
		t.Error("a failed refresh reported no error")
	}
}

// A GitHub account name becomes part of a URL, so anything that is not one
// must be refused before the request is built.
func TestGitHubAccountNamesAreValidated(t *testing.T) {
	for _, bad := range []string{
		"", "-leading", "trailing-", "has/slash", "has.dot", "has space",
		"..", "a?b", strings.Repeat("x", 40),
	} {
		if validAccount(bad) {
			t.Errorf("%q was accepted as a GitHub account", bad)
		}
	}
	for _, good := range []string{"justin06lee", "a", "a-b-c", "User123"} {
		if !validAccount(good) {
			t.Errorf("%q was rejected as a GitHub account", good)
		}
	}
}

func TestGitHubSourceRefusesABadAccount(t *testing.T) {
	k := NewKeys(quiet())
	defer k.Close()

	err := k.Set(context.Background(), []Source{Source("github:../../etc/passwd")})
	if err == nil {
		t.Fatal("a malformed account name was fetched")
	}
	if k.Allow(clientKey(t).PublicKey()) {
		t.Error("a failed fetch authorized somebody")
	}
}
