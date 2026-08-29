package relay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/justin06lee/makima/internal/key"
)

// DefaultStatePath is where a relay keeps its identity.
const DefaultStatePath = "/var/lib/makima/relay.json"

// Identity is a relay's persistent state, which is only its keypair.
//
// A relay is otherwise entirely stateless: it learns who is connected from the
// connections themselves and forgets when they close. The key has to persist
// because nodes pin it — a relay that regenerated its key on restart would be
// rejected by every node that had been told what to expect, which is precisely
// what pinning is for.
type Identity struct {
	PrivateKey key.Private `json:"private_key"`
}

// LoadIdentity reads a relay's key, generating one on first run.
func LoadIdentity(path string) (*Identity, error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var id Identity
		if err := json.Unmarshal(b, &id); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if id.PrivateKey.IsZero() {
			return nil, fmt.Errorf("%s: no relay key", path)
		}
		return &id, nil

	case os.IsNotExist(err):
		priv, err := key.NewPrivate()
		if err != nil {
			return nil, err
		}
		id := &Identity{PrivateKey: priv}
		if err := SaveIdentity(path, id); err != nil {
			return nil, err
		}
		return id, nil

	default:
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
}

// SaveIdentity writes a relay's key.
//
// Mode 0600, and write-then-rename for the same reason every other state file
// in makima does it: a torn write here means a new identity on next start and
// a mesh full of nodes that refuse to connect.
func SaveIdentity(path string, id *Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create relay state dir: %w", err)
	}

	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".makima-relay-*")
	if err != nil {
		return fmt.Errorf("create temp relay state: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
