// Package conf loads and saves a node's on-disk identity.
//
// In M0 this file is the entire control plane: you write the peer list by
// hand. From M1 the same struct is filled by the control server and the file
// shrinks to just the node's own keys and server URL, which is why the shape
// is a netmap.NetMap rather than something bespoke.
package conf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/justin06lee/makima/internal/netmap"
)

// DefaultPath is where the daemon looks when no path is given. The daemon
// needs root to create a TUN device anyway, so a root-owned location costs
// nothing and keeps the private key out of a user-writable directory.
const DefaultPath = "/etc/makima/node.json"

// Load reads a node configuration.
func Load(path string) (*netmap.NetMap, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var m netmap.NetMap
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m.PrivateKey.IsZero() {
		return nil, fmt.Errorf("%s: no private key; run 'makima init' first", path)
	}
	if len(m.Self.Addresses) == 0 {
		return nil, fmt.Errorf("%s: node has no mesh address", path)
	}
	return &m, nil
}

// Save writes a node configuration, creating the directory if needed.
//
// Mode 0600 because this file holds the node's private key — the one secret
// whose disclosure lets someone else impersonate this machine on the mesh.
func Save(path string, m *netmap.NetMap) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
