// Package control is the coordination plane: the service that decides who is
// in the mesh and who may talk to whom, and the client that asks it.
//
// It never sees a private key and never carries a packet. Compromising it
// buys an attacker the ability to lie about membership — to introduce a node
// that should not exist — and nothing else. That specific weakness is what
// node-key signing closes later; the split of duties that makes it the *only*
// weakness is established here.
package control

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/policy"
)

// ProtocolVersion guards against a node and server disagreeing about the wire
// format after an upgrade. Bump it on any breaking change to the types below.
//
// Version 2 added the relay assignment, disco key, and signature fields that
// M2, M3 and M6 need. A version-1 node and a version-2 server share no
// messages, which is the honest outcome: the older node has no way to be told
// about a relay it does not know how to use.
const ProtocolVersion = 2

// Envelope wraps every control message.
//
// The machine key travels in the clear because the server must know whose key
// to attempt decryption with; everything meaningful is inside Payload. There
// is no separate authentication step, and that is deliberate: only the holder
// of the matching private key can produce a payload that opens, so a
// successful decryption *is* the authentication.
type Envelope struct {
	Version    int        `json:"version"`
	MachineKey key.Public `json:"machine_key"`
	Nonce      []byte     `json:"nonce"`
	Payload    []byte     `json:"payload"`
}

// RegisterRequest asks to join the mesh.
type RegisterRequest struct {
	Name      string           `json:"name"`
	NodeKey   key.Public       `json:"node_key"`
	DiscoKey  key.Public       `json:"disco_key"`
	AuthKey   string           `json:"auth_key"`
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`

	// AdvertiseRoutes are subnets this node offers to route for the mesh, and
	// AdvertiseExit that it offers to carry general internet traffic. Both are
	// requests, not assertions: nothing is published until approved.
	AdvertiseRoutes []netip.Prefix `json:"advertise_routes,omitempty"`
	AdvertiseExit   bool           `json:"advertise_exit,omitempty"`
}

// RegisterResponse is the server's answer to a join.
type RegisterResponse struct {
	NodeID  netmap.NodeID `json:"node_id"`
	Address netip.Prefix  `json:"address"`
	Error   string        `json:"error,omitempty"`

	// PendingRoutes are advertised routes still awaiting approval, so the CLI
	// can tell an operator what to go and approve rather than leaving them to
	// wonder why nothing is routing.
	PendingRoutes []netip.Prefix `json:"pending_routes,omitempty"`
	PendingExit   bool           `json:"pending_exit,omitempty"`
}

// MapRequest asks for the caller's view of the mesh.
//
// Version is the last netmap the caller successfully applied. The server holds
// the request open until it has something newer, which is what turns polling
// into push without either side maintaining a connection protocol of its own.
type MapRequest struct {
	Version   uint64           `json:"version"`
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`
}

// MapResponse is one node's complete view of the mesh.
type MapResponse struct {
	Version uint64        `json:"version"`
	Self    netmap.Node   `json:"self"`
	Peers   []netmap.Node `json:"peers"`
	Error   string        `json:"error,omitempty"`

	// HomeRelay is where this node should connect, and where peers will look
	// for it when no direct path exists.
	HomeRelay netmap.Relay `json:"home_relay,omitzero"`

	// Filter is the compiled access policy this node enforces on ingress. Nil
	// means no policy, which is allow-all.
	Filter *policy.Filter `json:"filter,omitempty"`

	// Domain and DNS configure mesh name resolution.
	Domain string           `json:"domain,omitempty"`
	DNS    netmap.DNSConfig `json:"dns,omitzero"`

	// Lock is the network lock's trusted keys, so a node can verify its peers'
	// signatures without asking the server what to trust — which would defeat
	// the point entirely.
	Lock *LockConfig `json:"lock,omitempty"`
}

// LockConfig is the part of the network lock a node needs.
type LockConfig struct {
	Enabled     bool         `json:"enabled"`
	TrustedKeys []SigningKey `json:"trusted_keys"`
}

// seal encrypts v to the recipient, authenticated as the sender.
func seal(v any, recipient key.Public, sender key.Private) (nonce, payload []byte, err error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, nil, fmt.Errorf("encode payload: %w", err)
	}
	return key.Seal(plain, recipient, sender)
}

// open decrypts a payload from sender into v.
func open(payload, nonce []byte, v any, sender key.Public, recipient key.Private) error {
	plain, err := key.Open(payload, nonce, sender, recipient)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	return nil
}

// Seal packages v into an Envelope addressed to recipient.
func Seal(v any, machineKey key.Public, recipient key.Public, sender key.Private) (*Envelope, error) {
	nonce, payload, err := seal(v, recipient, sender)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Version:    ProtocolVersion,
		MachineKey: machineKey,
		Nonce:      nonce,
		Payload:    payload,
	}, nil
}

// Open unwraps an Envelope into v, verifying it came from sender.
func (e *Envelope) Open(v any, sender key.Public, recipient key.Private) error {
	if e.Version != ProtocolVersion {
		return fmt.Errorf("protocol version %d, want %d", e.Version, ProtocolVersion)
	}
	return open(e.Payload, e.Nonce, v, sender, recipient)
}
