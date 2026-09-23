package control

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// clientTimeout must exceed pollTimeout, or every long poll is cancelled by
// our own transport just before the server would have answered — which looks
// exactly like a flaky network and is maddening to diagnose.
const clientTimeout = pollTimeout + 30*time.Second

// dialTimeout bounds connecting to one of the control plane's addresses.
//
// Far shorter than the default, because it is what decides how long a laptop
// that has left the house spends knocking on the LAN address before trying the
// public one. A control plane that takes eight seconds to accept a TCP
// connection is not one worth waiting on.
const dialTimeout = 8 * time.Second

// Client talks to a control plane on behalf of one node.
type Client struct {
	serverKey  key.Public
	machineKey key.Private
	http       *http.Client

	// urls are every address the control plane answers at: the one the node
	// joined through first, then whatever others the server has named. cur is
	// the one currently in use, kept until it stops answering — so a node
	// that had to fall back stays on the address that works rather than
	// retrying the dead one on every poll.
	mu   sync.Mutex
	urls []string
	cur  int
}

// NewClient builds a client for a known server key.
func NewClient(baseURL string, serverKey key.Public, machineKey key.Private) *Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext
	return &Client{
		urls:       []string{strings.TrimRight(baseURL, "/")},
		serverKey:  serverKey,
		machineKey: machineKey,
		http:       &http.Client{Timeout: clientTimeout, Transport: t},
	}
}

// BaseURL is the address this client is currently reaching the control plane
// at.
func (c *Client) BaseURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.urls[c.cur]
}

// SetAlternates records the other addresses the control plane answers at.
//
// The address the node joined through stays first, and whichever one is in
// use stays in use: learning about a new address is no reason to leave one
// that works.
func (c *Client) SetAlternates(alts []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	current := c.urls[c.cur]
	urls := []string{c.urls[0]}
	for _, a := range alts {
		a = strings.TrimRight(strings.TrimSpace(a), "/")
		if a != "" && !slices.Contains(urls, a) {
			urls = append(urls, a)
		}
	}
	c.urls = urls
	c.cur = max(slices.Index(urls, current), 0)
}

// FetchServerKey retrieves the control plane's public key.
//
// Only for bootstrapping a node whose invitation did not pin one. Trusting the
// network for this single round trip is a real, if narrow, exposure: whoever
// answers becomes the control plane. Pin the key in the join command when the
// server is reachable over anything you do not control.
func FetchServerKey(ctx context.Context, baseURL string) (key.Public, error) {
	kr, err := fetchKey(ctx, baseURL, "")
	if err != nil {
		return key.Public{}, err
	}
	return kr.ServerKey, nil
}

// FetchServerKeyVerified fetches the key on behalf of somebody holding an
// invite's words, and refuses one the server cannot vouch for.
//
// This is the words' answer to the question the mk1_ string answered by
// carrying the key: a machine in the middle can hand over any key it likes,
// but it cannot produce a MAC under a key it has never seen.
func FetchServerKeyVerified(ctx context.Context, baseURL, handle string, macKey []byte) (key.Public, error) {
	kr, err := fetchKey(ctx, baseURL, handle)
	if err != nil {
		return key.Public{}, err
	}
	m := hmac.New(sha256.New, macKey)
	m.Write(kr.ServerKey[:])
	if !hmac.Equal(m.Sum(nil), kr.MAC) {
		return key.Public{}, errors.New("the server at " + baseURL + " is not the one these words are for — something between here and there answered in its place")
	}
	return kr.ServerKey, nil
}

func fetchKey(ctx context.Context, baseURL, handle string) (keyResponse, error) {
	u, err := url.JoinPath(strings.TrimRight(baseURL, "/"), "key")
	if err != nil {
		return keyResponse{}, fmt.Errorf("build key URL: %w", err)
	}
	if handle != "" {
		u += "?invite=" + url.QueryEscape(handle)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return keyResponse{}, err
	}

	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return keyResponse{}, fmt.Errorf("reach control server: %w", err)
	}
	defer resp.Body.Close()

	body := io.LimitReader(resp.Body, 1<<16)
	if resp.StatusCode == http.StatusNotFound && handle != "" {
		var e struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(body).Decode(&e) == nil && e.Error != "" {
			return keyResponse{}, errors.New(e.Error)
		}
		return keyResponse{}, errors.New("this network does not know that invite")
	}
	if resp.StatusCode != http.StatusOK {
		return keyResponse{}, fmt.Errorf("control server returned %s", resp.Status)
	}

	var kr keyResponse
	if err := json.NewDecoder(body).Decode(&kr); err != nil {
		return keyResponse{}, fmt.Errorf("decode server key: %w", err)
	}
	if kr.Version != ProtocolVersion {
		return keyResponse{}, fmt.Errorf("server speaks protocol %d, we speak %d", kr.Version, ProtocolVersion)
	}
	if kr.ServerKey.IsZero() {
		return keyResponse{}, fmt.Errorf("server returned an empty key")
	}
	return kr, nil
}

// Register joins or updates this node.
func (c *Client) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.roundTrip(ctx, "machine/register", req, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("control server refused registration: %s", resp.Error)
	}
	return &resp, nil
}

// PollMap asks for a netmap newer than version, blocking until one exists or
// the server's heartbeat fires.
func (c *Client) PollMap(ctx context.Context, version uint64, endpoints []netip.AddrPort) (*MapResponse, error) {
	return c.Poll(ctx, &MapRequest{Version: version, Endpoints: endpoints})
}

// Poll is PollMap with everything a node reports about itself.
func (c *Client) Poll(ctx context.Context, req *MapRequest) (*MapResponse, error) {
	var resp MapResponse
	if err := c.roundTrip(ctx, "machine/map", req, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("control server: %s", resp.Error)
	}

	resp.stripServerSuppliedSecrets()

	return &resp, nil
}

// errNoSuchEndpoint is a control plane that answered, and does not know the
// request: one older than the request is.
var errNoSuchEndpoint = errors.New("the control plane does not know this request")

// ErrNoRemoteUpdates is a control plane too old to pass an update order on.
var ErrNoRemoteUpdates = errors.New("the control plane runs a makima from before remote updates")

// RequestUpdate asks the control plane to move every node to a release.
func (c *Client) RequestUpdate(ctx context.Context, tag string) (UpdateOrder, error) {
	var resp UpdateResponse
	if err := c.roundTrip(ctx, "machine/update", &UpdateRequest{Tag: tag}, &resp); err != nil {
		if errors.Is(err, errNoSuchEndpoint) {
			return UpdateOrder{}, ErrNoRemoteUpdates
		}
		return UpdateOrder{}, err
	}
	if resp.Error != "" {
		return UpdateOrder{}, errors.New(resp.Error)
	}
	return resp.Order, nil
}

// roundTrip seals req, posts it, and opens the reply into resp — at the
// address in use, and then at each of the others until one answers.
//
// Anything short of a sealed reply counts as not answering, not only a failed
// connection. Away from home, the LAN address can belong to some other
// machine entirely — a hotel's router with a web page on 8080 — and the only
// thing that proves an answer came from this control plane is that it opens
// under the server's key.
func (c *Client) roundTrip(ctx context.Context, path string, req, resp any) error {
	env, err := Seal(req, c.machineKey.Public(), c.serverKey, c.machineKey)
	if err != nil {
		return err
	}

	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}

	c.mu.Lock()
	urls := append([]string(nil), c.urls...)
	start := c.cur
	c.mu.Unlock()

	var errs []string
	missing := true
	for i := range urls {
		idx := (start + i) % len(urls)
		err := c.post(ctx, urls[idx], path, body, resp)
		if err == nil {
			if idx != start {
				c.mu.Lock()
				if c.cur == start && idx < len(c.urls) && c.urls[idx] == urls[idx] {
					c.cur = idx
				}
				c.mu.Unlock()
			}
			return nil
		}
		if len(urls) == 1 || ctx.Err() != nil {
			return err
		}
		// A 404 proves nothing on its own — it is also what a stranger's web
		// server at the LAN address says — so the other addresses are still
		// tried. Only if every one of them says it is it the server's answer.
		if !errors.Is(err, errNoSuchEndpoint) {
			missing = false
		}
		errs = append(errs, fmt.Sprintf("%s: %v", urls[idx], err))
	}
	if missing {
		return fmt.Errorf("%w: %s", errNoSuchEndpoint, path)
	}
	return fmt.Errorf("no address of the control server answered — %s", strings.Join(errs, "; "))
}

// post sends one sealed request to one address and opens the reply.
func (c *Client) post(ctx context.Context, base, path string, body []byte, resp any) error {
	u, err := url.JoinPath(base, path)
	if err != nil {
		return fmt.Errorf("build URL: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("reach control server: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("control server rejected our machine key (is this node registered?)")
	}
	if httpResp.StatusCode == http.StatusNotFound || httpResp.StatusCode == http.StatusMethodNotAllowed {
		return fmt.Errorf("%w: %s", errNoSuchEndpoint, path)
	}
	if httpResp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
		return fmt.Errorf("control server returned %s: %s", httpResp.Status, strings.TrimSpace(string(msg)))
	}

	var replyEnv Envelope
	if err := json.NewDecoder(io.LimitReader(httpResp.Body, 1<<22)).Decode(&replyEnv); err != nil {
		return fmt.Errorf("decode reply envelope: %w", err)
	}
	if err := replyEnv.Open(resp, c.serverKey, c.machineKey); err != nil {
		return fmt.Errorf("open reply: %w", err)
	}
	return nil
}
