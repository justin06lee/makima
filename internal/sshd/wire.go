package sshd

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"

	"github.com/creack/pty"
)

// The payloads of the session requests this server understands, parsed here
// rather than inline so the bounds checks are in one place. Every one of these
// arrives from a client that has authenticated but is otherwise untrusted.

// parseString reads one SSH string: a 32-bit length and that many bytes.
func parseString(b []byte) (string, error) {
	if len(b) < 4 {
		return "", errors.New("sshd: truncated string")
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint64(n) > uint64(len(b)-4) {
		return "", errors.New("sshd: string claims more bytes than the payload holds")
	}
	return string(b[4 : 4+n]), nil
}

// ptyRequest is a client's terminal, and the handle to resize it later.
type ptyRequest struct {
	term          string
	width, height uint32

	mu sync.Mutex
	f  *os.File
}

// parsePTYRequest reads a pty-req payload: TERM, then columns, rows, and two
// pixel dimensions nobody uses.
func parsePTYRequest(b []byte) (*ptyRequest, error) {
	term, err := parseString(b)
	if err != nil {
		return nil, err
	}
	rest := b[4+len(term):]
	if len(rest) < 16 {
		return nil, errors.New("sshd: truncated pty-req")
	}
	return &ptyRequest{
		term:   term,
		width:  binary.BigEndian.Uint32(rest[0:4]),
		height: binary.BigEndian.Uint32(rest[4:8]),
	}, nil
}

// parseWindowChange reads a window-change payload.
func parseWindowChange(b []byte) (width, height uint32, err error) {
	if len(b) < 16 {
		return 0, 0, errors.New("sshd: truncated window-change")
	}
	return binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint32(b[4:8]), nil
}

// attach records the terminal this request is driving.
func (p *ptyRequest) attach(f *os.File) {
	p.mu.Lock()
	p.f = f
	p.mu.Unlock()
}

// resize applies a window-change to a running terminal.
//
// Guarded because window-change arrives on the request loop while the session
// is being served, so this genuinely races with attach.
func (p *ptyRequest) resize(width, height uint32) {
	p.mu.Lock()
	p.width, p.height = width, height
	f := p.f
	p.mu.Unlock()

	if f != nil {
		_ = pty.Setsize(f, sizeOf(width, height))
	}
}

// winsize is the terminal size to start with.
func (p *ptyRequest) winsize() *pty.Winsize {
	p.mu.Lock()
	defer p.mu.Unlock()
	return sizeOf(p.width, p.height)
}

// sizeOf clamps a client-supplied window to something a terminal can be.
//
// Zero is what a client sends when it does not know, and a terminal eighty
// columns wide is a far better guess than one zero columns wide. The upper
// bound is there because the values are attacker-controlled and end up in an
// ioctl.
func sizeOf(width, height uint32) *pty.Winsize {
	if width == 0 || width > 1<<14 {
		width = 80
	}
	if height == 0 || height > 1<<14 {
		height = 24
	}
	return &pty.Winsize{Cols: uint16(width), Rows: uint16(height)}
}
