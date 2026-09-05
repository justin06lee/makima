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
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// clientTimeout must exceed pollTimeout, or every long poll is cancelled by
// our own transport just before the server would have answered — which looks
// exactly like a flaky network and is maddening to diagnose.
const clientTimeout = pollTimeout + 30*time.Second

// Client talks to a control plane on behalf of one node.
type Client struct {
	baseURL    string
	serverKey  key.Public
	machineKey key.Private
	http       *http.Client
}

// NewClient builds a client for a known server key.
func NewClient(baseURL string, serverKey key.Public, machineKey key.Private) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		serverKey:  serverKey,
		machineKey: machineKey,
		http:       &http.Client{Timeout: clientTimeout},
	}
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
	req := &MapRequest{Version: version, Endpoints: endpoints}

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

// roundTrip seals req, posts it, and opens the reply into resp.
func (c *Client) roundTrip(ctx context.Context, path string, req, resp any) error {
	env, err := Seal(req, c.machineKey.Public(), c.serverKey, c.machineKey)
	if err != nil {
		return err
	}

	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}

	u, err := url.JoinPath(c.baseURL, path)
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
