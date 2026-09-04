// Package conf loads and saves a node's on-disk identity.
//
// A node runs in one of two modes and the file says which:
//
//	static   no LoginServer. The peer list in this file is the whole mesh,
//	         maintained by hand. It stays supported because it is the only mode
//	         that needs no infrastructure at all — and because it is the only
//	         one where WireGuard gets an ordinary UDP socket.
//	managed  LoginServer set. The peer list here is only a cache of the last
//	         netmap the control server sent, so a node that boots while the
//	         server is unreachable still comes up with the mesh it last knew.
package conf

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/serve"
)

// DefaultPath is where the daemon looks when no path is given. The daemon
// needs root to create a TUN device anyway, so a root-owned location costs
// nothing and keeps the private keys out of a user-writable directory.
const DefaultPath = "/etc/makima/node.json"

// File is a node's complete on-disk state.
type File struct {
	// NodeKey is the WireGuard key. Rotatable: changing it and
	// re-registering is a normal operation, which is why the control plane
	// keys identity off MachineKey instead.
	NodeKey key.Private `json:"node_key"`

	// MachineKey is this device's permanent identity to the control server,
	// and the key its control channel is sealed under.
	MachineKey key.Private `json:"machine_key"`

	// DiscoKey authenticates NAT-traversal probes, so path discovery can run
	// before any WireGuard session exists.
	DiscoKey key.Private `json:"disco_key"`

	ListenPort uint16 `json:"listen_port"`

	// LoginServer empty means static mode.
	LoginServer string     `json:"login_server,omitempty"`
	ServerKey   key.Public `json:"server_key,omitzero"`

	// AuthKey is a join credential held only between `makima join` and the
	// daemon's first successful registration, then cleared. It exists because
	// a node that is expired by an operator has to present one again, and
	// prompting for it on a headless machine is not an option.
	AuthKey string `json:"auth_key,omitempty"`

	// AdvertiseRoutes and AdvertiseExit are this node's standing offers to
	// route for the mesh. Requests, not facts: nothing takes effect until the
	// control plane says it was approved.
	AdvertiseRoutes []netip.Prefix `json:"advertise_routes,omitempty"`
	AdvertiseExit   bool           `json:"advertise_exit,omitempty"`

	// ExitNode is the peer this node routes its own traffic through, by name.
	// Empty means normal routing.
	ExitNode string `json:"exit_node,omitempty"`

	// Services are the local ports this node publishes on its mesh address.
	//
	// The target half stays here and is never sent anywhere. The control plane
	// learns only which mesh port is open, because that is all any other node
	// needs and telling it more would publish this machine's internal layout.
	Services []serve.Service `json:"services,omitempty"`

	// DeniedPorts are ports this node must never publish, even when something
	// is listening on them.
	//
	// Needed because loopback services are published automatically: without a
	// record of the refusal, withdrawing one would last until the next scan
	// noticed it again five seconds later. This is what makes "deny" mean
	// "keep it off the mesh" rather than "take it off the mesh for a moment".
	DeniedPorts []uint16 `json:"denied_ports,omitempty"`

	// Domain and HomeRelay cache what the last netmap said, so a node that
	// starts while the control server is unreachable still comes up with mesh
	// DNS and a relay rather than isolated.
	Domain    string       `json:"domain,omitempty"`
	HomeRelay netmap.Relay `json:"home_relay,omitzero"`

	Self  netmap.Node   `json:"self"`
	Peers []netmap.Node `json:"peers,omitempty"`
}

// NewIdentity generates a node's three keypairs.
func NewIdentity() (nodeKey, machineKey, discoKey key.Private, err error) {
	if nodeKey, err = key.NewPrivate(); err != nil {
		return
	}
	if machineKey, err = key.NewPrivate(); err != nil {
		return
	}
	discoKey, err = key.NewPrivate()
	return
}

// Managed reports whether a control server owns this node's peer list.
func (f *File) Managed() bool { return f.LoginServer != "" }

// AdvertisedServices renders the local service list into the form the control
// plane is told about: which mesh ports are open, and nothing else.
func (f *File) AdvertisedServices() []netmap.Service {
	if len(f.Services) == 0 {
		return nil
	}
	out := make([]netmap.Service, 0, len(f.Services))
	for _, s := range f.Services {
		out = append(out, netmap.Service{
			Name:   s.Name,
			Port:   s.Port,
			Scheme: netmap.GuessScheme(s.Port),
		})
	}
	return out
}

// NetMap renders the file into the mesh view the daemon consumes.
func (f *File) NetMap() *netmap.NetMap {
	return &netmap.NetMap{
		PrivateKey: f.NodeKey,
		ListenPort: f.ListenPort,
		Self:       f.Self,
		Peers:      f.Peers,
		HomeRelay:  f.HomeRelay,
		Domain:     f.Domain,
	}
}

// Load reads a node configuration.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.NodeKey.IsZero() {
		return nil, fmt.Errorf("%s: no node key; run 'makima init' or 'makima join' first", path)
	}
	if f.MachineKey.IsZero() {
		return nil, fmt.Errorf("%s: no machine key; this config predates the control plane, re-run 'makima init -force'", path)
	}
	// A managed node legitimately has no address until its first successful
	// registration, so only static mode can demand one up front.
	if !f.Managed() && len(f.Self.Addresses) == 0 {
		return nil, fmt.Errorf("%s: node has no mesh address", path)
	}
	return &f, nil
}

// Save writes a node configuration, creating the directory if needed.
//
// Mode 0600 because this file holds all three private keys — the secrets whose
// disclosure lets someone else be this machine on the mesh.
func Save(path string, f *File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	b = append(b, '\n')

	// Write-then-rename: a node that loses its keys to a torn write has to be
	// re-admitted to the mesh by hand, and the daemon rewrites this file on
	// every netmap update.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".makima-node-*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}
