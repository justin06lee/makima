// Package drop moves a file from one machine on the mesh to another.
//
// makima could reach every port on every machine you own and still not have a
// way to send a file, which is the thing people actually want to do second,
// after getting a shell. Every workaround is worse than it looks: scp needs an
// sshd and an account, a web server needs somewhere to put the file first, and
// a chat client sends it to a stranger's datacentre and back.
//
// The protocol is deliberately small, because the hard parts are already done.
// A connection arriving here came over WireGuard from a peer whose key is in
// this node's configuration, so it is already encrypted, already authenticated,
// and already from somebody who was admitted on purpose. There is nothing left
// for a transfer protocol to prove, so it does not try: a header, the bytes,
// and an answer.
//
// What is left is the part being on a trusted network does *not* solve.
// Receiving a file means letting another machine create one here, and a peer
// that is trusted to reach a port is not thereby trusted to choose a path on
// this filesystem. Everything in the receiver exists for that: one directory,
// base names only, no overwrites, a size cap, and files written readable by
// their owner alone.
package drop

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Port is where a node listens for incoming files.
//
// Beside the relay's 3478 rather than something memorable: it is bound only on
// the mesh address, so it never collides with anything the host is running and
// never appears on any other interface.
const Port = 3479

// ProtocolVersion guards against two ends disagreeing about framing.
const ProtocolVersion = 1

// magic prefixes every transfer, so connecting to the wrong port fails
// immediately and clearly rather than hanging on a header that never comes.
var magic = [8]byte{'m', 'a', 'k', 'i', 'd', 'r', 'o', 'p'}

// MaxHeader bounds the JSON header. A file name is the only unbounded thing in
// it, and no filesystem accepts one anywhere near this long.
const MaxHeader = 8 << 10

// DefaultMaxSize is the largest file a receiver accepts by default.
//
// Generous rather than unlimited. The cap is not really about disk — it is
// about a peer being able to fill it while nobody is watching, and a number
// that can be raised on purpose is better than a surprise at 3am.
const DefaultMaxSize = 8 << 30 // 8 GiB

// Header describes an incoming file.
type Header struct {
	// Name is what to call the file. Only ever its base name: the receiver
	// strips any path, and refuses anything that still looks like one.
	Name string `json:"name"`

	// Size is the number of bytes to follow. Checked against the cap before
	// anything is created, so an oversized transfer is refused rather than
	// half-written and deleted.
	Size int64 `json:"size"`

	// Mode carries the executable bit and nothing else. A sender does not get
	// to choose the permissions of a file on somebody else's machine, but
	// losing the executable bit on a script is a real annoyance.
	Mode uint32 `json:"mode,omitempty"`

	// From names the sending machine, for the log line. Cosmetic and
	// unverified — the peer's identity comes from WireGuard, not from here.
	From string `json:"from,omitempty"`
}

// Result is what the receiver says when it is done.
type Result struct {
	OK bool `json:"ok"`

	// Path is where the file landed, which may not be the name that was sent:
	// the receiver renames rather than overwrites.
	Path string `json:"path,omitempty"`

	Error string `json:"error,omitempty"`
}

// ErrRefused reports a transfer the far end would not accept.
var ErrRefused = errors.New("drop: refused")

// writeFrame emits a length-prefixed JSON value.
func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxHeader {
		return fmt.Errorf("drop: header is %d bytes, over the %d-byte limit", len(b), MaxHeader)
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// readFrame reads one length-prefixed JSON value.
func readFrame(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > MaxHeader {
		// Do not attempt to resynchronise: a length this large means the
		// stream is not what we think it is.
		return fmt.Errorf("drop: header claims %d bytes, over the %d-byte limit", size, MaxHeader)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// SafeName reduces a sender-supplied name to something that can only ever
// create a file directly inside the inbox.
//
// This is the whole of the receiver's path handling, kept in one function so
// the claim is checkable. A peer is trusted to reach a port; that is not the
// same as being trusted to choose a path on this filesystem, and the two are
// easy to conflate because everything else about the connection is already
// authenticated.
func SafeName(name string) (string, error) {
	// Both separators, because a Windows sender's backslash is not a
	// separator to filepath.Base on Unix and would survive as part of the
	// name — "..\..\x" as a single filename is not an escape, but it is not
	// something anyone meant either.
	name = strings.ReplaceAll(name, `\`, "/")
	name = filepath.Base(name)
	name = strings.TrimSpace(name)

	switch name {
	case "", ".", "..", "/":
		return "", errors.New("drop: the file has no usable name")
	}
	if strings.ContainsRune(name, os.PathSeparator) || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("drop: %q is not a plain file name", name)
	}
	// A leading dot is allowed — dotfiles are ordinary — but a name that is
	// nothing but dots is not.
	if strings.Trim(name, ".") == "" {
		return "", fmt.Errorf("drop: %q is not a plain file name", name)
	}
	return name, nil
}

// UniqueName finds a name in dir that does not exist yet.
//
// Never overwriting is the point. A peer sending "notes.txt" twice, or two
// peers each sending their own, must not silently destroy the first — and the
// alternative, refusing the second, turns a transfer into a negotiation.
// Renaming is what both other tools people already use do.
func UniqueName(dir, name string) (string, error) {
	candidate := filepath.Join(dir, name)
	if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
		return candidate, nil
	}

	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)

	for i := 2; i < 1000; i++ {
		candidate = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("drop: too many files already named like %q", name)
}

// dialTimeout bounds reaching a peer. Short: the address is on the mesh, so
// either the tunnel is up or it is not.
const dialTimeout = 15 * time.Second

const idleTimeout = 60 * time.Second

// idleTimeout bounds a stalled transfer.
//
// An *idle* deadline rather than a total one, and pushed forward every time
// bytes actually move: see internal/drop/idle.go for why the distinction is
// the whole design. A transfer running at one byte a second survives; one that
// stops dead is closed within this window.
