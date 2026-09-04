package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/serve"
)

// ErrNoDaemon reports that nothing is listening on the socket.
//
// A distinct error because it is by far the most common one, and because the
// right response to it — "start the daemon" — is different from the response
// to anything else that can go wrong here.
var ErrNoDaemon = errors.New("no makimad is running")

// Client talks to a running daemon.
type Client struct {
	http *http.Client
	path string
}

// dialSocket is the transport every client here uses: the address is ignored
// and the connection always goes to one Unix socket.
func dialSocket(socketPath string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
}

// Dial connects to the daemon's socket.
func Dial(socketPath string) (*Client, error) {
	c, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w (looked at %s)", ErrNoDaemon, socketPath)
	}
	c.Close()

	return &Client{
		path: socketPath,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: dialSocket(socketPath),
		},
	}, nil
}

// withTimeout returns a client to the same daemon that will wait longer.
//
// The default is deliberately short: every other call is a local read or a
// file write, and one that takes thirty seconds has hung. Pairing is the
// exception — it blocks on a machine somewhere else answering — so it gets its
// own client rather than loosening the bound for everything.
func (c *Client) withTimeout(d time.Duration) *Client {
	return &Client{
		path: c.path,
		http: &http.Client{Timeout: d, Transport: dialSocket(c.path)},
	}
}

// Status fetches the daemon's view of itself.
func (c *Client) Status() (Status, error) {
	var s Status
	err := c.call(http.MethodGet, "/api/status", nil, &s)
	return s, err
}

// Diagnose runs the daemon's checks.
func (c *Client) Diagnose() (Diagnosis, error) {
	var d Diagnosis
	err := c.call(http.MethodGet, "/api/doctor", nil, &d)
	return d, err
}

// Serve publishes a port.
func (c *Client) Serve(spec, name string) error {
	return c.call(http.MethodPost, "/api/serve", ServeRequest{Spec: spec, Name: name}, nil)
}

// Unserve withdraws one.
func (c *Client) Unserve(port uint16) error {
	return c.call(http.MethodPost, "/api/unserve", ServeRequest{Port: port}, nil)
}

// SetExitNode selects an exit node, or clears it when name is empty.
func (c *Client) SetExitNode(name string) error {
	return c.call(http.MethodPost, "/api/exit-node", ExitNodeRequest{Name: name}, nil)
}

// AllowFirewall asks the daemon to trust the tunnel interface.
func (c *Client) AllowFirewall() (netcfg.Report, error) {
	var r netcfg.Report
	err := c.call(http.MethodPost, "/api/firewall/allow", nil, &r)
	return r, err
}

func (c *Client) call(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}

	// The host is ignored for a Unix socket but net/http insists on one.
	req, err := http.NewRequest(method, "http://makimad"+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reach the daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("daemon returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// maxSocketPath is how long a Unix socket path may be.
//
// The limit is sockaddr_un.sun_path: 104 bytes on macOS and the BSDs, 108 on
// Linux, both including the terminating NUL. Exceeding it fails with a bare
// EINVAL — "invalid argument", with no hint that length is the problem.
//
// The control plane enforces the same limit on its own socket for the same
// reason. Checked separately here rather than shared, because the alternative
// is this package importing the entire coordination protocol to borrow twelve
// lines, and the two sockets are derived from different paths anyway.
const maxSocketPath = 100

// CheckSocketPath reports whether a socket path is usable.
func CheckSocketPath(path string) error {
	if len(path) > maxSocketPath {
		return fmt.Errorf(
			"the daemon's socket path is %d bytes, over the %d-byte limit the OS imposes on Unix sockets:\n  %s\nuse a shorter -config path",
			len(path), maxSocketPath, path)
	}
	return nil
}

// ListenSocket opens the daemon's local socket.
//
// A socket left behind by a crash would make every subsequent start fail with
// "address already in use", so a stale one is removed — but only after
// confirming nothing is listening, or this would steal the socket from a
// healthy daemon and leave two of them answering for one node.
func ListenSocket(path string) (net.Listener, error) {
	if err := CheckSocketPath(path); err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); err == nil {
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("another makimad is already running on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	// Owner-only: the socket *is* the authorisation, and reaching it already
	// requires being able to write the node's private keys.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return ln, nil
}

// ServiceLine renders a service for the CLI's status output.
func ServiceLine(s serve.Status) string {
	state := "listening"
	switch {
	case s.Error != "":
		state = "FAILED: " + s.Error
	case !s.Listening:
		state = "not listening"
	case !s.TargetUp:
		state = "NOTHING ON " + s.Target
	}
	return fmt.Sprintf("%-24s %s", s.Service.String(), state)
}

// OpenPairing publishes a pairing address on this node and returns it.
func (c *Client) OpenPairing(seconds int) (PairingState, error) {
	var st PairingState
	err := c.call("POST", "/api/pair", PairRequest{Seconds: seconds}, &st)
	return st, err
}

// ClosePairing stops this node answering knocks.
func (c *Client) ClosePairing() error {
	return c.call("POST", "/api/pair/close", nil, nil)
}

// Pair knocks on another machine's pairing address, waiting up to wait for an
// answer.
//
// Hanging up is how a knock is cancelled: the daemon takes the request's
// context from the connection, so a client that gives up stops the knocking
// rather than leaving it running on the other side of the socket.
func (c *Client) Pair(address string, wait time.Duration) (PairedResult, error) {
	var res PairedResult
	// A little more than the caller asked for, so the timeout that fires is
	// the daemon's — which knows what it was waiting for — rather than this
	// one, which would only be able to say "deadline exceeded".
	err := c.withTimeout(wait+5*time.Second).call("POST", "/api/pair", PairRequest{Address: address}, &res)
	return res, err
}

// Ping probes one peer and reports how this node is currently reaching it.
func (c *Client) Ping(name string) (Ping, error) {
	var p Ping
	err := c.call(http.MethodGet, "/api/ping?peer="+url.QueryEscape(name), nil, &p)
	return p, err
}
