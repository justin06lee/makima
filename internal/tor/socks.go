package tor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// socksDial opens a connection to host:port through Tor's SOCKS port.
//
// SOCKS5 with the name sent as a name, never resolved here: an onion address
// has no IP to resolve to, and Tor is the only thing that knows what to do
// with one. Written out rather than imported because what matters most is
// the failure — Tor's extended replies say whether the service is unpublished,
// unreachable or simply slow, and that is what a person needs to be told.
func socksDial(ctx context.Context, proxy, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("port %q: %w", portStr, err)
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("name too long for SOCKS: %q", host)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("reach tor: %w", err)
	}

	// The handshake runs under the caller's deadline, or ctx's cancellation;
	// an onion circuit can take tens of seconds, and nothing else bounds it.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if err := socksHandshake(conn, host, uint16(port)); err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("reach %s over tor: %w", host, ctx.Err())
		}
		return nil, err
	}
	if !stop() {
		conn.Close()
		return nil, fmt.Errorf("reach %s over tor: %w", host, ctx.Err())
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func socksHandshake(conn net.Conn, host string, port uint16) error {
	// Version 5, one method offered: none. The port is loopback and Tor's.
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return fmt.Errorf("tor's socks port: %w", err)
	}
	if choice[0] != 5 || choice[1] != 0 {
		return fmt.Errorf("tor's socks port refused the handshake (%d %d)", choice[0], choice[1])
	}

	req := make([]byte, 0, 7+len(host))
	req = append(req, 5, 1, 0, 3, byte(len(host)))
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("tor's socks port: %w", err)
	}
	if head[1] != 0 {
		return &DialError{Host: host, Code: head[1]}
	}

	// The bound address, which means nothing for a connection made through
	// Tor but has to be read past.
	var skip int
	switch head[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return err
		}
		skip = int(n[0])
	default:
		return fmt.Errorf("tor's socks port: address type %d", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return err
	}
	return nil
}

// DialError is Tor saying why it could not connect.
type DialError struct {
	Host string
	Code byte
}

func (e *DialError) Error() string {
	return fmt.Sprintf("reach %s over tor: %s", e.Host, socksReason(e.Code))
}

// Unpublished reports whether the onion service could not be found at all —
// the server is down, or has not published yet — as opposed to found and not
// answering.
func (e *DialError) Unpublished() bool { return e.Code == 0xF0 }

// socksReason words a SOCKS reply code, Tor's extended ones included.
func socksReason(code byte) string {
	switch code {
	case 1:
		return "tor could not connect"
	case 2:
		return "tor's policy refused the connection"
	case 3:
		return "the network is unreachable"
	case 4:
		return "the host is unreachable"
	case 5:
		return "the connection was refused at the far end"
	case 6:
		return "it took too long"
	case 0xF0:
		return "the onion service is not published — its server is off, or has only just started"
	case 0xF1:
		return "the onion service's descriptor is invalid"
	case 0xF2:
		return "the onion service did not answer the introduction"
	case 0xF3:
		return "the onion service did not meet at the rendezvous"
	case 0xF4, 0xF5:
		return "the onion service wants client authorization"
	case 0xF6:
		return "that is not a valid onion address"
	case 0xF7:
		return "the onion service took too long to answer"
	}
	return fmt.Sprintf("tor failed (code %#x)", code)
}

// errNotOnion is a dial to something Tor is not used for.
var errNotOnion = errors.New("tor: not an onion address")
