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

	"github.com/justin06lee/makima/internal/bypass"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/tor"
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

	// joined is the address the node joined through, and alts the others
	// the control plane has named; urls are all of them, best first — see
	// rank. cur is the one in use, kept while it answers, so a node that had
	// to fall back stays on an address that works rather than retrying a
	// dead one on every poll; "" until one has answered, and after Rehome.
	mu     sync.Mutex
	joined string
	alts   []string
	urls   []string
	cur    string

	// local is where this control plane answered on this machine's own
	// loopback: the machine holds the network. localDown is when it stopped
	// answering there, zero while it answers. See candidates.
	local     string
	localDown time.Time

	// probed is when better addresses than cur were last looked for, and
	// probing that a look is under way. parked are the polls held open at
	// an address, so one at a worse address can be moved. See lookForBetter.
	probed  time.Time
	probing bool
	parked  map[*parkedPoll]struct{}

	// binder keeps the connections to the control plane out of an exit
	// node's tunnel. Nil for a client that never needs to. Guarded by mu.
	binder *bypass.Binder
}

// NewClient builds a client for a known server key.
func NewClient(baseURL string, serverKey key.Public, machineKey key.Private) *Client {
	c := &Client{
		joined:     strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		serverKey:  serverKey,
		machineKey: machineKey,
		parked:     make(map[*parkedPoll]struct{}),
	}
	c.urls = rank(c.joined, nil, "")
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		c.mu.Lock()
		b := c.binder
		c.mu.Unlock()
		return b.DialContext(ctx, d, network, address)
	}
	c.http = &http.Client{Timeout: clientTimeout, Transport: t}
	return c
}

// SetBinder keeps this client's connections out of an exit node's tunnel.
func (c *Client) SetBinder(b *bypass.Binder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.binder = b
}

// DropConnections closes the connections kept for reuse, so the next request
// dials afresh — after the socket binding changed, the kept ones are going
// out the wrong way.
func (c *Client) DropConnections() { c.http.CloseIdleConnections() }

// BaseURL is the address this client is currently reaching the control plane
// at, or the best one it knows before any has answered.
func (c *Client) BaseURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.cur != "":
		return c.cur
	case len(c.urls) == 0:
		return ""
	}
	return c.urls[0]
}

// SetAlternates records the other addresses the control plane answers at.
//
// Whichever one is in use stays in use until a better one has been seen to
// answer: a node at home told the server's LAN address goes there, and a
// node in a café told the same is not dropped off the onion address that
// works for one that cannot. See lookForBetter.
func (c *Client) SetAlternates(alts []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var clean []string
	for _, a := range alts {
		a = strings.TrimRight(strings.TrimSpace(a), "/")
		if a != "" && !slices.Contains(clean, a) {
			clean = append(clean, a)
		}
	}
	c.alts = clean
	c.rerankLocked()
	// Something better than the address in use may be among them: look now,
	// not in half a minute.
	c.probed = time.Time{}
}

// Rehome chooses again, from the best address down, the next time one is
// needed.
//
// For a network change: the address in use was the one that answered on the
// old network — the onion address, from a café — and the best one, usually
// the home network's, answers again, and far faster, once the laptop is
// back.
func (c *Client) Rehome() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rerankLocked()
	c.cur = ""
}

// rerankLocked orders the addresses again, after they or this machine's own
// addresses changed. Callers hold mu.
func (c *Client) rerankLocked() {
	c.urls = rank(c.joined, c.alts, c.local)
	if !slices.Contains(c.urls, c.cur) {
		c.cur = ""
	}
}

// FetchServerKey retrieves the control plane's public key.
//
// Only for bootstrapping a node whose invitation did not pin one. Trusting the
// network for this single round trip is a real, if narrow, exposure: whoever
// answers becomes the control plane. Pin the key in the join command when the
// server is reachable over anything you do not control.
//
// b says how to dial, an onion address included; nil dials directly.
func FetchServerKey(ctx context.Context, b *bypass.Binder, baseURL string) (key.Public, error) {
	kr, err := fetchKey(ctx, b, baseURL, "")
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
func FetchServerKeyVerified(ctx context.Context, b *bypass.Binder, baseURL, handle string, macKey []byte) (key.Public, error) {
	kr, err := fetchKey(ctx, b, baseURL, handle)
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

func fetchKey(ctx context.Context, b *bypass.Binder, baseURL, handle string) (keyResponse, error) {
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

	// An onion address is found and connected to through tor, which can
	// take most of a minute the first time; anything else either answers in
	// seconds or is not going to.
	timeout := 15 * time.Second
	if tor.IsOnion(req.URL.Host) {
		timeout = tor.ConnectTimeout
	}
	d := &net.Dialer{Timeout: dialTimeout}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return b.DialContext(ctx, d, network, address)
	}
	c := &http.Client{Timeout: timeout, Transport: t}
	defer c.CloseIdleConnections()
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

// ErrNoLeave is a control plane too old to let a machine take itself off.
var ErrNoLeave = errors.New("the control plane runs a makima from before machines could leave on their own")

// Leave asks the control plane to forget this machine, so that every other
// node drops it. It names the machine that was forgotten, or returns "" when
// the control plane had no machine with this key.
func (c *Client) Leave(ctx context.Context) (string, error) {
	var resp LeaveResponse
	if err := c.roundTrip(ctx, "machine/leave", &LeaveRequest{Leave: true, At: time.Now()}, &resp); err != nil {
		if errors.Is(err, errNoSuchEndpoint) {
			return "", ErrNoLeave
		}
		return "", err
	}
	if resp.Error != "" {
		return "", errors.New(resp.Error)
	}
	return resp.Name, nil
}

// roundTrip seals req, posts it, and opens the reply into resp — at the
// address in use, and then at the others, best first, until one answers.
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

	// A poll moved to a better address is sent again there; each move is
	// to a better one, so this ends.
	for {
		err := c.send(ctx, path, body, resp)
		if errors.Is(err, errMoved) && ctx.Err() == nil {
			continue
		}
		return err
	}
}

// send is one pass of roundTrip over the addresses.
func (c *Client) send(ctx context.Context, path string, body []byte, resp any) error {
	c.mu.Lock()
	start := c.cur
	c.mu.Unlock()
	c.lookForBetter()

	var (
		errs           []string
		last           error
		tried, missing int
	)
	attempt := func(u string) error {
		err := c.post(ctx, u, path, body, resp)
		if err == nil {
			c.answered(start, u)
			return nil
		}
		if errors.Is(err, errMoved) || ctx.Err() != nil {
			return err
		}
		c.failed(u)
		tried++
		// A 404 proves nothing on its own — it is also what a stranger's web
		// server at the LAN address says — so the other addresses are still
		// tried. Only if every one of them says it is it the server's answer.
		if errors.Is(err, errNoSuchEndpoint) {
			missing++
		}
		last = err
		errs = append(errs, fmt.Sprintf("%s: %v", u, err))
		return err
	}

	if start != "" {
		if err := attempt(start); err == nil || errors.Is(err, errMoved) || ctx.Err() != nil {
			return err
		}
	}
	order, unanswered := c.candidates(ctx, start)
	errs = append(errs, unanswered...)
	for _, u := range order {
		if err := attempt(u); err == nil || errors.Is(err, errMoved) || ctx.Err() != nil {
			return err
		}
	}

	switch {
	case len(errs) == 1 && last != nil:
		// One address, and it said why.
		return last
	case tried > 0 && missing == tried:
		return fmt.Errorf("%w: %s", errNoSuchEndpoint, path)
	case len(errs) == 0:
		return errors.New("no address of the control server to try")
	}
	return fmt.Errorf("no address of the control server answered — %s", strings.Join(errs, "; "))
}

// post sends one sealed request to one address and opens the reply.
//
// A poll is parked while it is held open, so that a better address answering
// in the meantime moves it there (errMoved) rather than leaving it a minute
// on tor.
func (c *Client) post(ctx context.Context, base, path string, body []byte, resp any) error {
	if path != "machine/map" {
		return c.postOnce(ctx, base, path, body, resp)
	}
	pctx, done := c.park(ctx, base)
	defer done()
	err := c.postOnce(pctx, base, path, body, resp)
	if err != nil && ctx.Err() == nil && errors.Is(context.Cause(pctx), errMoved) {
		return errMoved
	}
	return err
}

func (c *Client) postOnce(ctx context.Context, base, path string, body []byte, resp any) error {
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
