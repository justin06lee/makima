package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A relay reached through a web server rather than on a port of its own.
//
// The point is that a machine only has to be reachable once. The control plane
// already answers HTTP on a port every node can get to — that is how they
// joined — so a relay carried on that same port is reachable by exactly the
// machines that can reach the control plane, through the same port forward,
// the same DNS name, the same reverse proxy. A separate relay port is one more
// thing to forward, and one more thing to be the reason a laptop in a hotel
// cannot get home.
//
// The mechanism is an HTTP/1.1 upgrade: an ordinary GET asking to switch
// protocols, answered with 101, after which the connection is the relay's own
// framing exactly as it is on the bare port.

// UpgradeProto is the protocol name a client asks to switch to.
const UpgradeProto = "makima-relay"

// Path is where a control plane carries its built-in relay.
//
// Handed to nodes as a URL relative to the control plane, so each resolves it
// against whichever address it is reaching the control plane at — the LAN
// address at home, a public name away — and the relay follows the node rather
// than being one more address to get wrong.
const Path = "/relay"

// Resolve turns a relay URL that is relative to the control plane into one a
// client can dial. Anything already absolute is returned unchanged.
func Resolve(relayURL, controlURL string) string {
	if !strings.HasPrefix(relayURL, "/") || controlURL == "" {
		return relayURL
	}
	return strings.TrimRight(controlURL, "/") + relayURL
}

// ServeHTTP takes over an upgraded HTTP connection and relays for it.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), UpgradeProto) {
		// Somebody opened the URL in a browser, most likely. Say what this is
		// rather than a bare 404, since the path is advertised to every node.
		http.Error(w, "this is a makima relay, for makima nodes only", http.StatusUpgradeRequired)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "this server cannot carry a relay", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}

	// The same caps as the bare port. A relay on a public web port is, if
	// anything, more exposed to the internet's background noise.
	if !s.admit(conn) {
		conn.Close()
		return
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	const switching = "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: " + UpgradeProto + "\r\n" +
		"Connection: Upgrade\r\n\r\n"
	if _, err := io.WriteString(conn, switching); err != nil {
		conn.Close()
		return
	}

	s.handle(withBuffered(conn, brw.Reader))
}

// dial connects to a relay: straight to its port, or through an HTTP upgrade
// when the address names a relay carried by a web server.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	addr, err := DialAddr(c.url)
	if err != nil {
		return nil, err
	}

	d := &net.Dialer{Timeout: dialTimeout}
	var conn net.Conn
	if c.dialer != nil {
		conn, err = c.dialer(ctx, d, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	u, isWeb := webRelay(c.url)
	if !isWeb {
		return conn, nil
	}

	if u.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname()})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls: %w", err)
		}
		conn = tc
	}

	upgraded, err := upgrade(conn, u)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return upgraded, nil
}

// upgrade asks an HTTP server to hand this connection to its relay.
func upgrade(conn net.Conn, u *url.URL) (net.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: " + UpgradeProto + "\r\n" +
		"Connection: Upgrade\r\n" +
		"User-Agent: makima\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("upgrade: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("no relay at %s (the server answered %s)", u.Redacted(), resp.Status)
	}

	// The relay speaks first, and its greeting may have arrived in the same
	// read as the 101 — so whatever the reader already holds belongs to the
	// relay session, not to HTTP.
	return withBuffered(conn, br), nil
}

// webRelay reports whether a relay address names a relay carried by a web
// server, as opposed to one listening on a port of its own.
//
// An https:// URL always does. An http:// URL does only when it has a path:
// "http://host:3478" has always meant the bare relay port, written the way an
// operator might write any address, and it has to keep meaning that. A path —
// "/relay" — is what says "a web server is in front of this".
func webRelay(s string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" {
		return nil, false
	}
	switch u.Scheme {
	case "https":
		return u, true
	case "http":
		return u, u.Path != "" && u.Path != "/"
	}
	return nil, false
}

// bufferedConn is a connection some of whose bytes were already read into a
// buffer — by the HTTP parser on either side of an upgrade.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if b.r.Buffered() > 0 {
		return b.r.Read(p)
	}
	return b.Conn.Read(p)
}

// withBuffered wraps conn only when the reader is holding something, so the
// common case stays a plain connection.
func withBuffered(conn net.Conn, r *bufio.Reader) net.Conn {
	if r == nil || r.Buffered() == 0 {
		return conn
	}
	return &bufferedConn{Conn: conn, r: r}
}
