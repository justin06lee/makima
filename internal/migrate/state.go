package migrate

// Input is what `makima migrate host` and `join` read on stdin when started
// from another machine: the invite, which is a credential and must not be on
// a command line, and the SSH keys for makima's own SSH server.
type Input struct {
	Invite  string `json:"invite,omitempty"`
	SSHKeys string `json:"ssh_keys,omitempty"`
}

// Retired is what `makima migrate retire` prints.
type Retired struct {
	Removed bool     `json:"removed"`
	Notes   []string `json:"notes,omitempty"`
}
