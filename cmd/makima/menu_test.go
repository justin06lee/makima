package main

import (
	"strings"
	"testing"
)

func threeItems() *menu {
	return newMenu("Possess tenet as:", []menuItem{
		{Label: "justin06lee", Note: "the account makima runs sessions as"},
		{Label: "deploy"},
		{Label: "root", Note: "the whole machine"},
	})
}

// feed drives a menu with bytes as a terminal would deliver them.
func feed(m *menu, in string) {
	keys, digits, _ := decode([]byte(in))
	for _, k := range keys {
		m.handle(k)
	}
	for _, d := range digits {
		m.pick(d)
	}
}

func TestArrowKeysMoveAndEnterChooses(t *testing.T) {
	m := threeItems()
	feed(m, "\x1b[B\x1b[B\r")
	if !m.done || m.chosen != 2 {
		t.Fatalf("down, down, enter chose %d (done=%v), want 2", m.chosen, m.done)
	}
}

func TestTheCursorStartsOnTheFirstItem(t *testing.T) {
	m := threeItems()
	feed(m, "\r")
	if m.chosen != 0 {
		t.Errorf("enter alone chose %d, want the first item", m.chosen)
	}
}

// The first item is the account somebody most likely wants and root is last,
// so enter alone must never be the dangerous one.
func TestEnterAloneNeverChoosesRoot(t *testing.T) {
	m := threeItems()
	feed(m, "\r")
	if m.items[m.chosen].Label == "root" {
		t.Error("enter with no movement chose root")
	}
}

func TestMovingWrapsAround(t *testing.T) {
	m := threeItems()
	feed(m, "\x1b[A") // up from the top
	if m.at != 2 {
		t.Errorf("up from the first item went to %d, want the last", m.at)
	}
	feed(m, "\x1b[B") // down from the bottom
	if m.at != 0 {
		t.Errorf("down from the last item went to %d, want the first", m.at)
	}
}

func TestVimAndEmacsKeysMoveToo(t *testing.T) {
	for _, in := range []string{"j\r", "\x0e\r", "\x1bOB\r"} {
		m := threeItems()
		feed(m, in)
		if m.chosen != 1 {
			t.Errorf("%q chose %d, want 1", in, m.chosen)
		}
	}
	for _, in := range []string{"jk\r", "j\x10\r", "j\x1bOA\r"} {
		m := threeItems()
		feed(m, in)
		if m.chosen != 0 {
			t.Errorf("%q chose %d, want 0", in, m.chosen)
		}
	}
}

func TestNumbersChooseDirectly(t *testing.T) {
	m := threeItems()
	feed(m, "3")
	if !m.done || m.chosen != 2 {
		t.Errorf("3 chose %d (done=%v), want 2", m.chosen, m.done)
	}

	// A number past the end is not a choice.
	m = threeItems()
	feed(m, "9")
	if m.done {
		t.Error("9 chose something in a list of three")
	}
}

func TestCancelKeys(t *testing.T) {
	for _, in := range []string{"\x1b", "q", "\x03", "\x04"} {
		m := threeItems()
		feed(m, in)
		if !m.done || m.chosen != -1 {
			t.Errorf("%q left done=%v chosen=%d, want cancelled", in, m.done, m.chosen)
		}
	}
}

// An escape that is the start of an arrow key must not read as cancel. Getting
// this wrong means the picker quits the moment somebody presses down.
func TestAnArrowIsNotAnEscape(t *testing.T) {
	m := threeItems()
	feed(m, "\x1b[B")
	if m.done {
		t.Fatal("an arrow key cancelled the picker")
	}
	if m.at != 1 {
		t.Errorf("the arrow moved to %d, want 1", m.at)
	}
}

// Terminals deliver bytes when they feel like it, so an escape sequence can
// arrive in pieces. The incomplete tail is left for the next read.
func TestASplitEscapeSequenceIsHeldOver(t *testing.T) {
	m := threeItems()

	keys, _, used := decode([]byte("\x1b["))
	if len(keys) != 0 {
		t.Fatalf("a half-read arrow produced %v", keys)
	}
	if used != 0 {
		t.Fatalf("consumed %d bytes of an incomplete sequence, want 0", used)
	}

	// The rest arrives; together they are one keypress.
	keys, _, used = decode([]byte("\x1b[B"))
	if len(keys) != 1 || keys[0] != keyDown || used != 3 {
		t.Fatalf("the completed sequence gave %v (%d bytes), want one down", keys, used)
	}
	for _, k := range keys {
		m.handle(k)
	}
	if m.at != 1 || m.done {
		t.Errorf("at=%d done=%v, want the cursor moved and the picker still open", m.at, m.done)
	}
}

// Somebody leaning on the arrow key sends many at once.
func TestSeveralKeypressesInOneRead(t *testing.T) {
	m := threeItems()
	feed(m, "\x1b[B\x1b[B\x1b[B\x1b[B\r")
	if m.chosen != 1 {
		t.Errorf("four downs and enter in one read chose %d, want 1 (wrapped)", m.chosen)
	}
}

func TestNothingHappensAfterTheListIsAnswered(t *testing.T) {
	m := threeItems()
	feed(m, "\r")
	at, chosen := m.at, m.chosen
	feed(m, "\x1b[B\x1b[B\r")
	if m.at != at || m.chosen != chosen {
		t.Error("the list moved after it had been answered")
	}
}

func TestRenderMarksTheCursorAndCountsItsLines(t *testing.T) {
	m := threeItems()
	m.handle(keyDown)

	plain := m.render(false)
	lines := strings.Split(strings.TrimSuffix(plain, "\r\n"), "\r\n")
	if len(lines) != m.lines() {
		t.Errorf("drew %d lines but reported %d — the redraw would drift", len(lines), m.lines())
	}
	if !strings.HasPrefix(lines[2], "› deploy") {
		t.Errorf("the cursor is not on the second item: %q", lines[2])
	}
	if strings.Contains(plain, "\x1b[") {
		t.Error("the colourless rendering still has escape codes in it")
	}
	if !strings.Contains(m.render(true), "\x1b[1m") {
		t.Error("the coloured rendering does not mark the cursor")
	}
}

// Every line ends in \r\n: in raw mode a bare newline drops a line without
// returning the carriage, and the list comes out as a staircase.
func TestEveryRenderedLineReturnsTheCarriage(t *testing.T) {
	out := threeItems().render(true)
	for _, line := range strings.Split(strings.TrimSuffix(out, "\r\n"), "\r\n") {
		if strings.Contains(line, "\n") {
			t.Errorf("a line contains a bare newline: %q", line)
		}
	}
}

func TestAnEmptyListAnswersNothing(t *testing.T) {
	m := newMenu("nothing here", nil)
	feed(m, "\r")
	if m.done {
		t.Error("an empty list was answered")
	}
}
