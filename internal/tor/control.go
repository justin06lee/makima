package tor

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// controlConn speaks Tor's control protocol: a line in, a reply out.
//
// Only the handful of commands makima needs, and no events — nothing here
// subscribes, so nothing arrives unasked and every reply belongs to the
// command just sent.
type controlConn struct {
	mu   sync.Mutex
	conn net.Conn
	r    *bufio.Reader
}

// commandTimeout bounds one command. Every command makima sends is answered
// from Tor's own memory; one that takes this long means Tor is wedged.
const commandTimeout = 30 * time.Second

func dialControl(addr string) (*controlConn, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("reach tor's control port: %w", err)
	}
	return &controlConn{conn: conn, r: bufio.NewReader(conn)}, nil
}

func (c *controlConn) Close() error { return c.conn.Close() }

// errReply is Tor refusing a command, with its status code and why.
type errReply struct {
	code int
	msg  string
}

func (e *errReply) Error() string { return fmt.Sprintf("tor said %d %s", e.code, e.msg) }

// cmd sends one command and returns the reply's lines, codes stripped. A
// "250+" data block is folded into its line, its body joined by newlines.
func (c *controlConn) cmd(line string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.conn.SetDeadline(time.Now().Add(commandTimeout)); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write([]byte(line + "\r\n")); err != nil {
		return nil, err
	}

	var out []string
	for {
		l, err := c.readLine()
		if err != nil {
			return nil, err
		}
		if len(l) < 4 {
			return nil, fmt.Errorf("tor: malformed reply %q", l)
		}
		code, err := strconv.Atoi(l[:3])
		if err != nil {
			return nil, fmt.Errorf("tor: malformed reply %q", l)
		}
		sep, text := l[3], l[4:]

		if code != 250 {
			// The final line of a refusal is the one that says why.
			if sep == ' ' {
				return nil, &errReply{code: code, msg: text}
			}
			continue
		}

		switch sep {
		case '-':
			out = append(out, text)
		case '+':
			var body []string
			for {
				d, err := c.readLine()
				if err != nil {
					return nil, err
				}
				if d == "." {
					break
				}
				body = append(body, strings.TrimPrefix(d, "."))
			}
			out = append(out, text+strings.Join(body, "\n"))
		case ' ':
			out = append(out, text)
			return out, nil
		default:
			return nil, fmt.Errorf("tor: malformed reply %q", l)
		}
	}
}

func (c *controlConn) readLine() (string, error) {
	l, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(l, "\r\n"), nil
}

// authenticate proves to Tor that this process may control it, by the cookie
// Tor wrote into its data directory — readable only by Tor's user and root.
func (c *controlConn) authenticate(cookie []byte) error {
	_, err := c.cmd("AUTHENTICATE " + hex.EncodeToString(cookie))
	return err
}

// getinfo asks for one value.
func (c *controlConn) getinfo(name string) (string, error) {
	lines, err := c.cmd("GETINFO " + name)
	if err != nil {
		return "", err
	}
	for _, l := range lines {
		if v, ok := strings.CutPrefix(l, name+"="); ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("tor did not answer GETINFO %s", name)
}

// bootstrap is how far Tor has got joining the network: 0 to 100, and what
// it is doing, as Tor words it.
type bootstrap struct {
	Progress int
	Summary  string
}

// bootstrapPhase reads status/bootstrap-phase:
//
//	NOTICE BOOTSTRAP PROGRESS=85 TAG=ap_handshake_done SUMMARY="Connected to a relay to build circuits"
func (c *controlConn) bootstrapPhase() (bootstrap, error) {
	v, err := c.getinfo("status/bootstrap-phase")
	if err != nil {
		return bootstrap{}, err
	}
	return parseBootstrap(v)
}

func parseBootstrap(v string) (bootstrap, error) {
	var b bootstrap
	found := false
	for _, kv := range splitQuoted(v) {
		k, val, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "PROGRESS":
			n, err := strconv.Atoi(val)
			if err != nil {
				return bootstrap{}, fmt.Errorf("tor: bootstrap progress %q", val)
			}
			b.Progress, found = n, true
		case "SUMMARY":
			b.Summary = unquote(val)
		}
	}
	if !found {
		return bootstrap{}, fmt.Errorf("tor: no bootstrap progress in %q", v)
	}
	return b, nil
}

// addOnion publishes an onion service under key, forwarding virtPort to
// target, and returns the service ID Tor derived from it.
//
// Not detached: the service lives exactly as long as this control connection,
// so a server that dies takes its onion service with it rather than leaving
// Tor answering for a port nobody listens on.
func (c *controlConn) addOnion(k Key, virtPort int, target string) (string, error) {
	lines, err := c.cmd(fmt.Sprintf("ADD_ONION %s Port=%d,%s", k.blob(), virtPort, target))
	if err != nil {
		return "", err
	}
	for _, l := range lines {
		if id, ok := strings.CutPrefix(l, "ServiceID="); ok {
			return id, nil
		}
	}
	return "", errors.New("tor published the onion service without naming it")
}

// delOnion takes an onion service down.
func (c *controlConn) delOnion(serviceID string) error {
	_, err := c.cmd("DEL_ONION " + serviceID)
	return err
}

// splitQuoted splits on spaces outside double quotes.
func splitQuoted(s string) []string {
	var (
		out   []string
		cur   strings.Builder
		quote bool
		esc   bool
	)
	for _, r := range s {
		switch {
		case esc:
			esc = false
		case r == '\\' && quote:
			esc = true
		case r == '"':
			quote = !quote
		case r == ' ' && !quote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// unquote strips a control-protocol quoted string's quotes and escapes, and
// leaves anything unquoted as it is.
func unquote(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	if u, err := strconv.Unquote(s); err == nil {
		return u
	}
	return s[1 : len(s)-1]
}
