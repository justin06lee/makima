package control

import (
	"net/http"
	"net/netip"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/policy"
)

// AddRelay registers a relay with the running server.
func (c *AdminClient) AddRelay(url string, k key.Public) error {
	return c.call(http.MethodPost, "/admin/relay/add", RelayRequest{URL: url, Key: k}, nil)
}

// RemoveRelay drops one.
func (c *AdminClient) RemoveRelay(url string) error {
	return c.call(http.MethodPost, "/admin/relay/rm", RelayRequest{URL: url}, nil)
}

// PreferRelay makes a relay the mesh's active one.
func (c *AdminClient) PreferRelay(url string) error {
	return c.call(http.MethodPost, "/admin/relay/prefer", RelayRequest{URL: url}, nil)
}

// Relays lists registered relays.
func (c *AdminClient) Relays() ([]netmap.Relay, error) {
	var out []netmap.Relay
	if err := c.call(http.MethodGet, "/admin/relay", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ApproveRoutes accepts a node's advertised subnets.
func (c *AdminClient) ApproveRoutes(name string, routes []netip.Prefix, exit, all bool) error {
	return c.call(http.MethodPost, "/admin/routes/approve",
		RoutesRequest{Name: name, Routes: routes, Exit: exit, All: all}, nil)
}

// RevokeRoutes withdraws approval.
func (c *AdminClient) RevokeRoutes(name string, routes []netip.Prefix, exit bool) error {
	return c.call(http.MethodPost, "/admin/routes/revoke",
		RoutesRequest{Name: name, Routes: routes, Exit: exit}, nil)
}

// SetTags replaces a node's policy tags.
func (c *AdminClient) SetTags(name string, tags []string) error {
	return c.call(http.MethodPost, "/admin/tags", TagsRequest{Name: name, Tags: tags}, nil)
}

// Expire forces a node to re-authenticate.
func (c *AdminClient) Expire(name string) error {
	return c.call(http.MethodPost, "/admin/expire", ForgetRequest{Name: name}, nil)
}

// Policy fetches the access-control policy.
func (c *AdminClient) Policy() (*policy.Policy, error) {
	var p policy.Policy
	if err := c.call(http.MethodGet, "/admin/policy", nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// SetPolicy replaces it.
func (c *AdminClient) SetPolicy(p *policy.Policy) error {
	return c.call(http.MethodPost, "/admin/policy", p, nil)
}

// DNS reports the mesh's name settings.
func (c *AdminClient) DNS() (DNSResponse, error) {
	var out DNSResponse
	err := c.call(http.MethodGet, "/admin/dns", nil, &out)
	return out, err
}

// SetDNS configures them.
func (c *AdminClient) SetDNS(enabled bool, domain string) error {
	return c.call(http.MethodPost, "/admin/dns", DNSRequest{Enabled: enabled, Domain: domain}, nil)
}

// LockStatus reports the network lock's state.
func (c *AdminClient) LockStatus() (LockStatus, error) {
	var out LockStatus
	err := c.call(http.MethodGet, "/admin/lock", nil, &out)
	return out, err
}

// PendingSignatures lists nodes awaiting a signature.
func (c *AdminClient) PendingSignatures() ([]UnsignedNode, error) {
	var out []UnsignedNode
	if err := c.call(http.MethodGet, "/admin/lock/pending", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddSigningKey trusts a new authority.
func (c *AdminClient) AddSigningKey(name string, pub []byte) error {
	return c.call(http.MethodPost, "/admin/lock/add-key", SigningKeyRequest{Name: name, Public: pub}, nil)
}

// RemoveSigningKey stops trusting one.
func (c *AdminClient) RemoveSigningKey(id string) error {
	return c.call(http.MethodPost, "/admin/lock/rm-key", SigningKeyRequest{ID: id}, nil)
}

// SetLockEnabled turns enforcement on or off.
func (c *AdminClient) SetLockEnabled(on bool) error {
	return c.call(http.MethodPost, "/admin/lock/enable", LockEnableRequest{Enabled: on}, nil)
}

// ApplySignature records a signature for a node.
func (c *AdminClient) ApplySignature(id netmap.NodeID, sig []byte) error {
	return c.call(http.MethodPost, "/admin/lock/sign", SignatureRequest{NodeID: id, Signature: sig}, nil)
}
