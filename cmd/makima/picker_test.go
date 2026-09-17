package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// onAPTY runs fn with stdin and stderr attached to a real terminal, returning
// everything that was drawn on it.
//
// A pty rather than a pipe because that is the whole difference: raw mode, the
// escape sequences and the check for "is anybody there" all behave differently
// on one, and those are the parts worth testing.
func onAPTY(t *testing.T, typed string, fn func()) string {
	t.Helper()

	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pty available here: %v", err)
	}
	defer ptmx.Close()
	defer tty.Close()

	oldIn, oldErr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = tty, tty
	defer func() { os.Stdin, os.Stderr = oldIn, oldErr }()

	var mu sync.Mutex
	var drawn bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				mu.Lock()
				drawn.Write(buf[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		// A moment for the first drawing, so the keystrokes land on a picker
		// that is already listening rather than racing it.
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(ptmx, typed)
	}()

	fn()

	mu.Lock()
	defer mu.Unlock()
	return drawn.String()
}

func TestChooseOnARealTerminal(t *testing.T) {
	items := []menuItem{
		{Label: "justin06lee", Note: "the account makima runs sessions as"},
		{Label: "root", Note: "the whole machine"},
	}

	var got int
	var err error
	drawn := onAPTY(t, "\x1b[B\r", func() {
		got, err = choose("Possess tenet as:", items)
	})

	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	if got != 1 {
		t.Errorf("chose %d, want 1 (root, after one down)", got)
	}
	if !strings.Contains(drawn, "Possess tenet as:") {
		t.Error("the title was never drawn")
	}
	for _, want := range []string{"justin06lee", "root", "the whole machine"} {
		if !strings.Contains(drawn, want) {
			t.Errorf("%q was never drawn", want)
		}
	}
	// The cursor is hidden while the list is up and put back afterwards.
	if !strings.Contains(drawn, "\x1b[?25l") || !strings.HasSuffix(strings.TrimRight(drawn, "\r"), "\x1b[?25h") {
		t.Error("the terminal cursor was not hidden and restored")
	}
}

// Escape leaves without choosing, and says so as an error rather than a
// silently wrong account.
func TestEscapeCancelsOnARealTerminal(t *testing.T) {
	var err error
	onAPTY(t, "\x1b", func() {
		_, err = choose("Possess tenet as:", []menuItem{{Label: "a"}, {Label: "b"}})
	})
	if err != ErrPickerCancelled {
		t.Errorf("escape returned %v, want ErrPickerCancelled", err)
	}
}

// Whatever happens, the terminal is left the way it was found. A picker that
// exits in raw mode leaves a shell where nothing you type appears.
func TestTheTerminalIsRestoredAfterwards(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pty available here: %v", err)
	}
	defer ptmx.Close()
	defer tty.Close()

	oldIn, oldErr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = tty, tty
	defer func() { os.Stdin, os.Stderr = oldIn, oldErr }()

	fd := int(tty.Fd())
	before, err := term.GetState(fd)
	if err != nil {
		t.Skipf("cannot read the terminal state: %v", err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := ptmx.Read(buf); err != nil {
				return
			}
		}
	}()
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(ptmx, "\r")
	}()

	if _, err := choose("pick:", []menuItem{{Label: "a"}, {Label: "b"}}); err != nil {
		t.Fatal(err)
	}

	after, err := term.GetState(fd)
	if err != nil {
		t.Fatal(err)
	}
	if *before != *after {
		t.Error("the terminal was left in a different mode than it was found in")
	}
}

// One account is not a question worth asking.
func TestASingleItemNeedsNoTerminal(t *testing.T) {
	got, err := choose("pick:", []menuItem{{Label: "only"}})
	if err != nil || got != 0 {
		t.Errorf("choose with one item returned (%d, %v), want (0, nil)", got, err)
	}
}

// And with nobody there, it refuses rather than picking for them.
func TestChooseRefusesWithoutATerminal(t *testing.T) {
	if _, err := choose("pick:", []menuItem{{Label: "a"}, {Label: "b"}}); err == nil {
		t.Error("a picker drawn to a pipe answered itself")
	}
}
