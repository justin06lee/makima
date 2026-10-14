package tor

import (
	"fmt"
	"os"
	"os/exec"
)

// credential stands in for syscall.Credential, which Windows has none of.
type credential struct{}

// prepareDataDir makes tor's data directory. Windows has no root to step
// down from; tor runs as whoever runs makima.
func prepareDataDir(dir string) (*credential, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create tor data directory: %w", err)
	}
	return nil, nil
}

func setCredential(*exec.Cmd, *credential) {}
