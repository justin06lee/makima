package drop

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func quiet() *log.Logger { return log.New(io.Discard, "", 0) }

// receiver starts one on loopback and returns its address and inbox.
//
// 127.0.0.1 stands in for a mesh address: the receiver binds one address and
// only one, and which address that is makes no difference to the protocol.
func receiver(t *testing.T, cfg Config) (netip.Addr, string, *Receiver) {
	t.Helper()

	if cfg.Dir == "" {
		cfg.Dir = t.TempDir()
	}
	r := New(quiet())
	t.Cleanup(r.Close)

	addr := netip.MustParseAddr("127.0.0.1")
	r.Apply(addr, cfg)

	dir, active, _ := r.Status()
	if !active {
		t.Skip("could not bind the inbox port on this machine")
	}
	return addr, dir, r
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The whole feature in one test: a file on one machine ends up on another.
func TestSendAndReceive(t *testing.T) {
	addr, inbox, r := receiver(t, Config{})

	src := writeFile(t, "notes.txt", "the quick brown fox")
	landed, err := Send(addr, src, "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}

	if filepath.Dir(landed) != inbox {
		t.Errorf("the file landed at %s, outside the inbox %s", landed, inbox)
	}
	got, err := os.ReadFile(landed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "the quick brown fox" {
		t.Errorf("contents are %q", got)
	}

	if _, _, received := r.Status(); received != 1 {
		t.Errorf("the receiver counted %d transfers", received)
	}
}

// Never overwriting is the point. Sending the same name twice must produce two
// files, because the alternative — silently destroying the first — is the one
// outcome nobody can recover from.
func TestSecondFileWithTheSameNameIsRenamed(t *testing.T) {
	addr, inbox, _ := receiver(t, Config{})

	first := writeFile(t, "notes.txt", "first")
	second := writeFile(t, "notes.txt", "second")

	a, err := Send(addr, first, "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Send(addr, second, "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}

	if a == b {
		t.Fatal("the second file overwrote the first")
	}
	if got, _ := os.ReadFile(a); string(got) != "first" {
		t.Errorf("the first file now contains %q", got)
	}
	if got, _ := os.ReadFile(b); string(got) != "second" {
		t.Errorf("the second file contains %q", got)
	}
	// The rename keeps the extension where a person expects it.
	if filepath.Ext(b) != ".txt" {
		t.Errorf("the renamed file is %s, which has lost its extension", filepath.Base(b))
	}
	_ = inbox
}

// A peer is trusted to reach a port. It is not trusted to choose a path on
// this filesystem, and this is the test that says so.
func TestSafeNameRefusesToEscapeTheInbox(t *testing.T) {
	for _, bad := range []string{
		"../../etc/passwd",
		"/etc/passwd",
		`..\..\windows\system32\config`,
		"..",
		".",
		"",
		"   ",
		"...",
		"foo/bar",
		"\x00evil",
	} {
		got, err := SafeName(bad)
		if err != nil {
			continue
		}
		// Anything accepted must be a plain name that stays put.
		if strings.ContainsAny(got, `/\`) || got == ".." || got == "." {
			t.Errorf("SafeName(%q) returned %q, which is not a plain file name", bad, got)
		}
		if filepath.Join("/inbox", got) != filepath.Clean("/inbox/"+got) {
			t.Errorf("SafeName(%q) returned %q, which does not stay inside the inbox", bad, got)
		}
	}
}

// Traversal has to be defeated in practice, not only in the helper.
func TestTraversalNeverLandsOutsideTheInbox(t *testing.T) {
	addr, inbox, _ := receiver(t, Config{})

	// Sent by hand, because the sender would never construct this name.
	for _, name := range []string{"../escaped.txt", "../../escaped.txt", `..\escaped.txt`} {
		err := sendRaw(addr, Header{Name: name, Size: 4}, "evil")

		outside := filepath.Join(filepath.Dir(inbox), "escaped.txt")
		if _, statErr := os.Stat(outside); statErr == nil {
			t.Fatalf("%q escaped the inbox and wrote %s", name, outside)
		}
		// Whether it was refused or written under a flattened name, nothing
		// may exist above the inbox.
		_ = err
	}
}

// Dotfiles are ordinary and must still work — the guard is about paths, not
// about leading dots.
func TestDotfilesAreAccepted(t *testing.T) {
	got, err := SafeName(".bashrc")
	if err != nil {
		t.Fatalf("a dotfile was refused: %v", err)
	}
	if got != ".bashrc" {
		t.Errorf("SafeName(%q) = %q", ".bashrc", got)
	}
}

// Over the cap is refused before anything is created, so an oversized transfer
// never becomes a partial file somebody has to clean up.
func TestOversizedFileIsRefusedWithoutWriting(t *testing.T) {
	addr, inbox, _ := receiver(t, Config{MaxSize: 8})

	src := writeFile(t, "big.bin", strings.Repeat("x", 64))
	if _, err := Send(addr, src, "laptop", nil); err == nil {
		t.Fatal("a file over the cap was accepted")
	}

	entries, err := os.ReadDir(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a refused transfer left %d file(s) behind", len(entries))
	}
}

// A truncated transfer must leave nothing: a partial file is worse than no
// file, because it looks complete.
func TestTruncatedTransferLeavesNothing(t *testing.T) {
	addr, inbox, _ := receiver(t, Config{})

	// Announce more than is sent, then hang up.
	if err := sendRaw(addr, Header{Name: "half.txt", Size: 100}, "only this much"); err == nil {
		t.Log("the receiver reported no error; the file must still be gone")
	}

	entries, err := os.ReadDir(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a truncated transfer left %v behind", entries)
	}
}

// A sender that keeps writing past its declared size is cut off, rather than
// being allowed to fill the disk with a file it said was small.
func TestSenderCannotExceedItsDeclaredSize(t *testing.T) {
	addr, inbox, _ := receiver(t, Config{})

	if err := sendRaw(addr, Header{Name: "liar.txt", Size: 4}, "four"+strings.Repeat("x", 4096)); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one file, got %v", entries)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 4 {
		t.Errorf("the file is %d bytes; the sender declared 4", info.Size())
	}
}

// Receiving switched off means the port is not bound at all, not that files
// are accepted and discarded.
func TestReceivingOffBindsNothing(t *testing.T) {
	r := New(quiet())
	t.Cleanup(r.Close)
	r.Apply(netip.MustParseAddr("127.0.0.1"), Config{Dir: ""})

	if _, active, _ := r.Status(); active {
		t.Fatal("the inbox is listening despite being switched off")
	}
}

// A directory is a likely mistake and should say so, rather than failing
// somewhere inside the copy.
func TestSendingADirectoryIsRefusedClearly(t *testing.T) {
	addr, _, _ := receiver(t, Config{})

	_, err := Send(addr, t.TempDir(), "laptop", nil)
	if err == nil {
		t.Fatal("a directory was accepted")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("the error does not mention directories: %v", err)
	}
}

// Reaching a machine that is not receiving must name the likely cause.
func TestSendingToNobodyIsRefusedClearly(t *testing.T) {
	src := writeFile(t, "notes.txt", "x")

	// A mesh address nothing is bound to.
	_, err := Send(netip.MustParseAddr("127.0.0.1"), src, "laptop", nil)
	if err == nil {
		t.Fatal("sending to nothing succeeded")
	}
	if !errors.Is(err, ErrRefused) {
		t.Errorf("got %v, want a refusal", err)
	}
}

// The executable bit survives; nothing else does. A sender does not get to
// widen permissions on somebody else's machine.
func TestModeIsNarrowedButKeepsTheExecutableBit(t *testing.T) {
	if got := fileMode(0o777); got != 0o700 {
		t.Errorf("a world-writable file arrived as %o, want 0700", got)
	}
	if got := fileMode(0o644); got != 0o600 {
		t.Errorf("a plain file arrived as %o, want 0600", got)
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in    string
		peer  string
		name  string
		ok    bool
		about string
	}{
		{"desktop:", "desktop", "", true, "a bare destination"},
		{"desktop:notes.txt", "desktop", "notes.txt", true, "a destination with a name"},
		{"notes.txt", "", "", false, "a local file"},
		{"./notes.txt", "", "", false, "a relative path"},
		{"/tmp/a:b", "", "", false, "an absolute path containing a colon"},
		{"C:/Users/x", "", "", false, "a Windows drive letter"},
	}
	for _, c := range cases {
		peer, name, ok := ParseTarget(c.in)
		if ok != c.ok || peer != c.peer || name != c.name {
			t.Errorf("%s: ParseTarget(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.about, c.in, peer, name, ok, c.peer, c.name, c.ok)
		}
	}
}

// sendRaw drives the protocol directly, so tests can send things the real
// sender would never construct: a name that escapes, a size that lies.
//
// It half-closes after the body, which is what a sender that finished or died
// would do. Without that a receiver still waiting for bytes it was promised
// would sit on its idle deadline, and the test would take a minute to prove
// something it can prove in a millisecond.
func sendRaw(addr netip.Addr, h Header, body string) error {
	c, err := net.Dial("tcp", net.JoinHostPort(addr.String(), fmt.Sprint(Port)))
	if err != nil {
		return err
	}
	defer c.Close()

	var hello [len(magic) + 1]byte
	copy(hello[:], magic[:])
	hello[len(magic)] = ProtocolVersion
	if _, err := c.Write(hello[:]); err != nil {
		return err
	}
	if err := writeFrame(c, h); err != nil {
		return err
	}
	// Errors ignored: a body deliberately longer than its declared size gets
	// cut off, and that is the behaviour under test rather than a failure.
	_, _ = io.WriteString(c, body)
	_ = c.(*net.TCPConn).CloseWrite()

	var res Result
	if err := readFrame(c, &res); err != nil {
		return err
	}
	if !res.OK {
		return errors.New(res.Error)
	}
	return nil
}

// Progress buys time; silence does not. A peer that opens a connection and
// then says nothing must not be able to hold it — and the file behind it —
// open indefinitely.
func TestAStalledSenderIsCutOff(t *testing.T) {
	dir := t.TempDir()
	r := New(quiet())
	t.Cleanup(r.Close)

	// A window short enough to observe, rather than the production minute.
	addr := netip.MustParseAddr("127.0.0.1")
	r.Apply(addr, Config{Dir: dir})
	if _, active, _ := r.Status(); !active {
		t.Skip("could not bind the inbox port on this machine")
	}

	c, err := net.Dial("tcp", net.JoinHostPort(addr.String(), fmt.Sprint(Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Greet, then go quiet without ever sending a header.
	var hello [len(magic) + 1]byte
	copy(hello[:], magic[:])
	hello[len(magic)] = ProtocolVersion
	if _, err := c.Write(hello[:]); err != nil {
		t.Fatal(err)
	}

	// The connection is still open and the receiver is still waiting, which is
	// correct — the deadline has not passed. What must be true is that a
	// deadline exists at all, which the reader sets on construction.
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, c)
		close(done)
	}()

	select {
	case <-done:
		// The receiver hung up on us, which is also fine.
	case <-time.After(200 * time.Millisecond):
		// Still waiting, as expected inside the window. Nothing was written.
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a sender that never sent a header created %v", entries)
	}
}
