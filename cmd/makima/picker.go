package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// The terminal half of the list: raw mode, escape sequences, and putting the
// terminal back however this exits.
//
// Everything here is about not leaving somebody's shell broken. Raw mode turns
// off echo and line buffering, and a process that exits without undoing it
// leaves a terminal where nothing you type appears — so the restore runs from
// a defer, before any error is returned and whether or not one is.

// ErrPickerCancelled reports a list the person backed out of.
var ErrPickerCancelled = errors.New("cancelled")

// interactive reports whether there is somebody at a terminal to answer.
//
// Both ends have to be one. A picker drawn to a pipe is invisible, and one
// reading from a file answers itself with whatever bytes happen to be there.
func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// choose draws a list and returns the index chosen, or ErrPickerCancelled.
//
// Drawn on stderr rather than stdout: `makima possess host cmd > file` should
// put the command's output in the file and the list on the screen, not the
// other way around.
func choose(title string, items []menuItem) (int, error) {
	if len(items) == 0 {
		return -1, errors.New("nothing to choose from")
	}
	if len(items) == 1 {
		return 0, nil
	}
	if !interactive() {
		return -1, errors.New("no terminal to ask at")
	}

	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return -1, err
	}

	m := newMenu(title, items)
	out := os.Stderr

	// One defer for the whole restore, so every path out of here — a chosen
	// item, a cancel, a read error, a panic — leaves the terminal usable.
	defer func() {
		fmt.Fprint(out, "\x1b[?25h")
		_ = term.Restore(fd, state)
	}()

	fmt.Fprint(out, "\x1b[?25l")
	fmt.Fprint(out, m.render(true))

	buf := make([]byte, 64)
	var pending []byte
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			keys, digits, used := decode(pending)
			pending = pending[used:]

			changed := false
			for _, k := range keys {
				if m.handle(k) {
					changed = true
				}
			}
			for _, d := range digits {
				if m.pick(d) {
					changed = true
				}
			}
			// Answered first, so the last keypress does not redraw a list
			// that is about to be erased.
			if m.done {
				erase(out, m.lines())
				if m.chosen < 0 {
					return -1, ErrPickerCancelled
				}
				return m.chosen, nil
			}
			if changed {
				erase(out, m.lines())
				fmt.Fprint(out, m.render(true))
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				erase(out, m.lines())
				return -1, ErrPickerCancelled
			}
			return -1, err
		}
	}
}

// erase moves back over the drawing and clears it, so the next one replaces it
// rather than scrolling underneath it.
func erase(out io.Writer, lines int) {
	for range lines {
		fmt.Fprint(out, "\x1b[1A\x1b[2K\r")
	}
}
