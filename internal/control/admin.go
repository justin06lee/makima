package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// The control plane's state is a single JSON file held in memory by whichever
// process opened it. That is fine for one process and actively wrong for two:
// a CLI that mints an auth key by editing the file directly is invisible to a
// running server, which still holds — and will later overwrite with — its own
// stale copy.
//
// So administration goes over a Unix socket to the running server rather than
// through the file. The socket's permissions are the entire access control
// story: reaching it already requires being able to write the state file, so
// there is no token to manage, rotate, or leak.

// SocketName is the admin socket, placed beside the state file so the two
// share a lifetime and a permission boundary.
const SocketName = "makima-server.sock"

// maxSocketPath is how long a Unix socket path may be.
//
// The limit is sockaddr_un.sun_path: 104 bytes on macOS and the BSDs, 108 on
// Linux, both including the terminating NUL. Exceeding it fails with a bare
// EINVAL — "invalid argument", with no hint that length is the problem — so
// the check here exists purely to turn that into an error a person can act on.
const maxSocketPath = 100

// SocketPath returns the admin socket for a given state file.
func SocketPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), SocketName)
}

// CheckSocketPath reports whether a socket path is usable.
func CheckSocketPath(path string) error {
	if len(path) > maxSocketPath {
		return fmt.Errorf(
			"admin socket path is %d bytes, over the %d-byte limit the OS imposes on Unix sockets:\n  %s\npass -socket with a shorter path, e.g. /tmp/makima.sock",
			len(path), maxSocketPath, path)
	}
	return nil
}

// AuthKeyRequest asks for a new join credential.
type AuthKeyRequest struct {
	Reusable bool          `json:"reusable"`
	TTL      time.Duration `json:"ttl"`
}

// ForgetRequest removes a node.
type ForgetRequest struct {
	Name string `json:"name"`
}

// adminError is the shape of a failed admin call.
type adminError struct {
	Error string `json:"error"`
}

// AdminHandler is the socket-only surface: everything the public handler
// serves, plus the administrative routes.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/", s.Handler())

	mux.HandleFunc("POST /admin/authkey", func(w http.ResponseWriter, r *http.Request) {
		var req AuthKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, adminError{err.Error()})
			return
		}
		a, err := s.store.MintAuthKey(req.Reusable, req.TTL)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, adminError{err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, a)
	})

	mux.HandleFunc("GET /admin/nodes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.Nodes())
	})

	mux.HandleFunc("POST /admin/forget", func(w http.ResponseWriter, r *http.Request) {
		var req ForgetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, adminError{err.Error()})
			return
		}
		if err := s.store.Forget(req.Name); err != nil {
			writeJSON(w, http.StatusNotFound, adminError{err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})

	mux.HandleFunc("GET /admin/key", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, keyResponse{
			Version:   ProtocolVersion,
			ServerKey: s.store.ServerKey().Public(),
		})
	})

	return mux
}

// ListenAdmin opens the admin socket.
//
// A socket left behind by a crashed server would make every subsequent start
// fail with "address already in use", so a stale one is removed — but only
// after confirming nothing is listening on it, or this would silently steal
// the socket from a healthy server and leave two processes fighting over the
// state file.
func ListenAdmin(path string) (net.Listener, error) {
	if err := CheckSocketPath(path); err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); err == nil {
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("another makima-server is already running on %s", path)
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
	// Owner-only: the socket *is* the authorisation.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return ln, nil
}

// AdminClient talks to a running server over its admin socket.
type AdminClient struct {
	http *http.Client
}

// DialAdmin connects to a running server. It returns false if none is
// listening, which is the normal case before the first start.
func DialAdmin(path string) (*AdminClient, bool) {
	if c, err := net.DialTimeout("unix", path, time.Second); err != nil {
		return nil, false
	} else {
		c.Close()
	}

	return &AdminClient{
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", path)
				},
			},
		},
	}, true
}

// MintAuthKey asks the running server for a join credential.
func (c *AdminClient) MintAuthKey(reusable bool, ttl time.Duration) (*AuthKey, error) {
	var a AuthKey
	if err := c.call(http.MethodPost, "/admin/authkey", AuthKeyRequest{Reusable: reusable, TTL: ttl}, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Nodes lists every registered node.
func (c *AdminClient) Nodes() ([]Node, error) {
	var nodes []Node
	if err := c.call(http.MethodGet, "/admin/nodes", nil, &nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

// Forget removes a node.
func (c *AdminClient) Forget(name string) error {
	return c.call(http.MethodPost, "/admin/forget", ForgetRequest{Name: name}, nil)
}

// ServerKey returns the control plane's public key.
func (c *AdminClient) ServerKey() (key.Public, error) {
	var kr keyResponse
	if err := c.call(http.MethodGet, "/admin/key", nil, &kr); err != nil {
		return key.Public{}, err
	}
	return kr.ServerKey, nil
}

func (c *AdminClient) call(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}

	// The host is ignored for a Unix socket but net/http insists on one.
	req, err := http.NewRequest(method, "http://makima"+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reach the running server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var e adminError
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("server returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
