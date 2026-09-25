package main

import (
	"flag"

	"github.com/justin06lee/makima/internal/control"
)

// Every administrative subcommand does the same dance: talk to the running
// server over its socket if one is listening, and operate on the state file
// directly if not. The two are not interchangeable — a running server holds
// the state in memory and would overwrite anything written behind its back —
// so the choice has to be made every time, and making it in one place is how
// it stays made correctly.

// adminFlags are the flags every administrative subcommand accepts.
type adminFlags struct {
	fs    *flag.FlagSet
	state *string
	sock  *string
}

func newAdminFlags(name string) *adminFlags {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return &adminFlags{
		fs:    fs,
		state: fs.String("state", DefaultStatePath, "path to control plane state"),
		sock:  fs.String("socket", "", "admin socket path (default: beside the state file)"),
	}
}

// target is either a live server or a store opened directly.
type target struct {
	admin *control.AdminClient
	store *control.Store
}

// live reports whether a running server is being addressed.
func (t *target) live() bool { return t.admin != nil }

// open resolves the flags into whichever of the two is appropriate.
func (a *adminFlags) open(args []string) (*target, error) {
	if err := a.fs.Parse(args); err != nil {
		return nil, err
	}

	path := sock(*a.sock, *a.state)
	if admin, ok := control.DialAdmin(path); ok {
		return &target{admin: admin}, nil
	}

	store, err := control.OpenStore(*a.state)
	if err != nil {
		return nil, err
	}
	return &target{store: store}, nil
}

// port is the port this network's server answers on; see serverPort.
func (t *target) port(statePath string) int { return serverPort(t.admin, statePath) }

// serverPort is the port the network's server answers on: the running
// server's own answer when there is one, what it last recorded beside its
// state when there is not, and only failing both, the default a new server
// would try first. Anything that prints an address for somebody to type or
// forward goes through here, so it names the port in use rather than 8080.
func serverPort(admin *control.AdminClient, statePath string) int {
	if admin != nil {
		if p, err := admin.ListenPort(); err == nil && p != 0 {
			return p
		}
	}
	if p := control.RecordedPort(statePath); p != 0 {
		return p
	}
	return control.DefaultPort
}
