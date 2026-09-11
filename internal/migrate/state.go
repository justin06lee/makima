package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// StatePath is where a machine being switched writes how it is going.
//
// In the log directory rather than beside makima's state, because it has to be
// readable without root: the machine that started the switch reads it back
// over SSH, as whoever it logged in as, and /var/lib/makima is root's alone.
// Nothing secret goes in it.
const StatePath = "/var/log/makima/migrate.json"

// LogPath is the switch's own log, for when the state is not enough.
const LogPath = "/var/log/makima/migrate.log"

// InputPath holds what a detached switch needs and the command line must not
// carry — the invite, which is a credential. Root's alone, and deleted the
// moment it is read.
const InputPath = "/var/lib/makima/migrate-input.json"

// The states a switch moves through.
const (
	StateStarting   = "starting"
	StateRunning    = "running"
	StateDone       = "done"        // on makima, Tailscale off (or kept, if asked)
	StateRolledBack = "rolled_back" // makima did not come up; Tailscale is back
	StateFailed     = "failed"      // could not even begin; nothing was changed
)

// State is one machine's switch, as it reports it.
type State struct {
	State   string    `json:"state"`
	Step    string    `json:"step,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Name    string    `json:"name,omitempty"`
	Address string    `json:"address,omitempty"`
	Path    string    `json:"path,omitempty"` // direct, or via a relay
	Removed bool      `json:"removed,omitempty"`
	Notes   []string  `json:"notes,omitempty"`
	PID     int       `json:"pid,omitempty"`
	Updated time.Time `json:"updated"`
}

// Final says the switch has finished, one way or the other.
func (s State) Final() bool {
	return s.State == StateDone || s.State == StateRolledBack || s.State == StateFailed
}

// WriteState replaces the state file in one step, so a reader never sees half
// of one.
func WriteState(path string, s State) error {
	s.Updated = time.Now().UTC()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadState parses a state file's contents.
func ReadState(b []byte) (State, error) {
	var s State
	err := json.Unmarshal(b, &s)
	return s, err
}

// Input is what a detached switch is handed.
type Input struct {
	Invite  string `json:"invite,omitempty"`
	SSHKeys string `json:"ssh_keys,omitempty"`
}
