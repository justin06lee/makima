package drop

import (
	"io"
	"net"
	"time"
)

// A transfer needs two deadlines that pull in opposite directions.
//
// A large file over a relayed path is legitimately slow for a very long time,
// so a total deadline would kill exactly the transfers that most needed to
// finish. But a connection with no deadline at all is a connection a stalled
// or hostile peer can hold open forever, along with the open file behind it.
//
// The resolution is an *idle* deadline, pushed forward every time bytes
// actually move. Progress buys more time; silence does not. A transfer running
// at one byte a second survives indefinitely; one that stops dead is closed
// within the window.

// idleReader wraps a connection so every successful read extends its deadline.
type idleReader struct {
	c      net.Conn
	window time.Duration
}

func newIdleReader(c net.Conn, window time.Duration) io.Reader {
	_ = c.SetReadDeadline(time.Now().Add(window))
	return &idleReader{c: c, window: window}
}

func (r *idleReader) Read(b []byte) (int, error) {
	n, err := r.c.Read(b)
	if n > 0 {
		// Only on progress. Extending on a zero-byte read would let a peer
		// that is doing nothing keep the connection alive.
		_ = r.c.SetReadDeadline(time.Now().Add(r.window))
	}
	return n, err
}

// idleWriter is the same idea on the sending side: a receiver that stops
// draining must not be able to park a sender forever.
type idleWriter struct {
	c      net.Conn
	window time.Duration
}

func newIdleWriter(c net.Conn, window time.Duration) io.Writer {
	_ = c.SetWriteDeadline(time.Now().Add(window))
	return &idleWriter{c: c, window: window}
}

func (w *idleWriter) Write(b []byte) (int, error) {
	n, err := w.c.Write(b)
	if n > 0 {
		_ = w.c.SetWriteDeadline(time.Now().Add(w.window))
	}
	return n, err
}
