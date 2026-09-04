package drop

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Send copies one local file to a peer's inbox.
//
// Returns where it landed on the far side, which is not always the name that
// was sent: the receiver renames rather than overwrites, and saying so is the
// difference between "sent" and "sent, and here is what to look for".
func Send(peer netip.Addr, path, from string, progress func(sent, total int64)) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory — send the files inside it, or an archive of it", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}

	addr := net.JoinHostPort(peer.String(), fmt.Sprint(Port))
	c, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return "", fmt.Errorf("%w: %s is not accepting files (is its daemon running, and receiving switched on?)", ErrRefused, peer)
	}
	defer c.Close()

	out := newIdleWriter(c, idleTimeout)

	var hello [len(magic) + 1]byte
	copy(hello[:], magic[:])
	hello[len(magic)] = ProtocolVersion
	if _, err := out.Write(hello[:]); err != nil {
		return "", err
	}

	h := Header{
		Name: filepath.Base(path),
		Size: info.Size(),
		Mode: uint32(info.Mode().Perm()),
		From: from,
	}
	if err := writeFrame(out, h); err != nil {
		return "", err
	}

	var w io.Writer = out
	if progress != nil {
		w = &progressWriter{w: out, total: info.Size(), report: progress}
	}
	if _, err := io.Copy(w, f); err != nil {
		return "", fmt.Errorf("send %s: %w", h.Name, err)
	}

	// The far end only answers once the file is fully written and synced, so
	// this is what turns "the bytes left here" into "the file is there". It
	// may take a moment on a large file, hence an idle deadline here too.
	var res Result
	if err := readFrame(newIdleReader(c, idleTimeout), &res); err != nil {
		return "", fmt.Errorf("%s did not confirm the transfer: %w", peer, err)
	}
	if !res.OK {
		if res.Error == "" {
			res.Error = "refused, with no reason given"
		}
		return "", fmt.Errorf("%w: %s", ErrRefused, res.Error)
	}
	return res.Path, nil
}

// progressWriter reports how far a transfer has got.
//
// Rate-limited to a few times a second rather than per write: a progress
// indicator that repaints on every 32KiB chunk spends more time on the
// terminal than on the file.
type progressWriter struct {
	w      io.Writer
	total  int64
	sent   int64
	last   time.Time
	report func(sent, total int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.sent += int64(n)

	if time.Since(p.last) > 100*time.Millisecond || p.sent == p.total {
		p.last = time.Now()
		p.report(p.sent, p.total)
	}
	return n, err
}

// ParseTarget splits "peer:" or "peer:name" into its two halves.
//
// The trailing colon marks an argument as remote, matching scp closely enough
// that nobody has to learn a second convention. An argument with no colon is a
// local path, which is how `makima cp a b desktop:` knows that only the last
// one is a destination.
func ParseTarget(s string) (peer, name string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}

	// A one-character prefix is a Windows drive letter, not a machine — and
	// no plausible machine name is one character either, so refusing both with
	// the same rule costs nothing.
	if i < 2 {
		return "", "", false
	}
	// An absolute path can contain a colon on some filesystems; it is still a
	// path, and treating "/tmp/a:b" as a peer would be a surprising way to
	// lose a file.
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// ErrNoDestination reports an argument list with nowhere to send to.
var ErrNoDestination = errors.New("cp needs a destination like 'desktop:' — 'makima status' lists the machines")
