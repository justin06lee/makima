package main

import (
	"fmt"
	"strings"
)

// A list you move through with the arrow keys and choose from with enter.
//
// Split in two on purpose: everything about *what the list does* is here and
// is ordinary Go that tests can drive, and the terminal — raw mode, escape
// sequences, restoring the cursor when something goes wrong — is in
// picker.go. A picker that can only be tested by a person pressing keys is one
// that gets tested once.

// menuItem is one line of the list.
type menuItem struct {
	// Label is what is chosen; Note is the grey half-sentence after it.
	Label string
	Note  string
}

// menu is the list's state.
type menu struct {
	title string
	items []menuItem
	at    int

	// done and chosen are set once the list has been answered. chosen is -1
	// when it was cancelled.
	done   bool
	chosen int
}

func newMenu(title string, items []menuItem) *menu {
	return &menu{title: title, items: items, chosen: -1}
}

// menuKey names the keys the list understands, so the terminal half can say
// what it read rather than passing bytes through.
type menuKey int

const (
	keyNone menuKey = iota
	keyUp
	keyDown
	keyEnter
	keyCancel
	keyTop
	keyBottom
)

// handle moves the cursor, or answers the list. It reports whether anything
// changed, so the caller only redraws when there is something to redraw.
func (m *menu) handle(k menuKey) bool {
	if m.done || len(m.items) == 0 {
		return false
	}

	switch k {
	case keyUp:
		if m.at == 0 {
			// Wrapping rather than stopping: with three items, the one at the
			// bottom is one keypress away from the top either way.
			m.at = len(m.items) - 1
		} else {
			m.at--
		}
	case keyDown:
		m.at = (m.at + 1) % len(m.items)
	case keyTop:
		m.at = 0
	case keyBottom:
		m.at = len(m.items) - 1
	case keyEnter:
		m.done, m.chosen = true, m.at
	case keyCancel:
		m.done, m.chosen = true, -1
	default:
		return false
	}
	return true
}

// pick selects by position, which is what a number key does. One-based,
// because the list is drawn that way.
func (m *menu) pick(n int) bool {
	if m.done || n < 1 || n > len(m.items) {
		return false
	}
	m.at = n - 1
	m.done, m.chosen = true, m.at
	return true
}

// decode turns what was read from the terminal into keys.
//
// Returns the keys it understood and how many bytes it consumed, so a partial
// escape sequence split across two reads is left for the next one rather than
// being mistaken for a bare escape.
func decode(b []byte) (keys []menuKey, digits []int, n int) {
	for n < len(b) {
		c := b[n]

		switch {
		case c == 0x1b:
			// An escape sequence, or the escape key on its own.
			if n+1 >= len(b) {
				if n == 0 && len(b) == 1 {
					// Nothing followed it in this read: the key itself.
					return append(keys, keyCancel), digits, n + 1
				}
				return keys, digits, n
			}
			if b[n+1] != '[' && b[n+1] != 'O' {
				keys = append(keys, keyCancel)
				n++
				continue
			}
			if n+2 >= len(b) {
				return keys, digits, n
			}
			switch b[n+2] {
			case 'A':
				keys = append(keys, keyUp)
			case 'B':
				keys = append(keys, keyDown)
			case 'H':
				keys = append(keys, keyTop)
			case 'F':
				keys = append(keys, keyBottom)
			}
			n += 3

		case c == '\r' || c == '\n':
			keys = append(keys, keyEnter)
			n++
		case c == 'k' || c == 'p' || c == 0x10: // ctrl-p
			keys = append(keys, keyUp)
			n++
		case c == 'j' || c == 'n' || c == 0x0e: // ctrl-n
			keys = append(keys, keyDown)
			n++
		case c == 'q' || c == 0x03 || c == 0x04: // ctrl-c, ctrl-d
			keys = append(keys, keyCancel)
			n++
		case c == 'g':
			keys = append(keys, keyTop)
			n++
		case c == 'G':
			keys = append(keys, keyBottom)
			n++
		case c >= '1' && c <= '9':
			digits = append(digits, int(c-'0'))
			n++
		default:
			n++
		}
	}
	return keys, digits, n
}

// render draws the list. The cursor line is marked and bold; the rest is
// plain, so which line is selected survives a terminal with no colour.
func (m *menu) render(colour bool) string {
	var b strings.Builder

	dim := func(s string) string {
		if !colour || s == "" {
			return s
		}
		return "\x1b[2m" + s + "\x1b[0m"
	}

	fmt.Fprintf(&b, "%s\r\n", m.title)
	for i, it := range m.items {
		line := fmt.Sprintf("  %s  %s", it.Label, dim(it.Note))
		if i == m.at {
			line = fmt.Sprintf("› %s  %s", it.Label, dim(it.Note))
			if colour {
				line = "\x1b[1m› " + it.Label + "\x1b[0m  " + dim(it.Note)
			}
		}
		fmt.Fprintf(&b, "%s\r\n", strings.TrimRight(line, " "))
	}
	b.WriteString(dim("  ↑↓ to move, enter to choose, esc to cancel"))
	b.WriteString("\r\n")
	return b.String()
}

// lines is how tall the drawing is, which is what the terminal half has to
// move back over to redraw it.
func (m *menu) lines() int { return len(m.items) + 2 }
