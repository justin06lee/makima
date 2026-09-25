package control

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// DefaultPort is where a network's server listens when nothing on the
// machine already does.
//
// Only a starting point. A machine that self-hosts often has something on
// 8080 already — tenet did — so a new server takes the next free port and
// records it (see ListenControl), and every part of makima that needs to know
// the port asks the server or reads that record rather than assuming this.
const DefaultPort = 8080

// portSearch is how many ports from DefaultPort a new server tries.
const portSearch = 100

// PortFile is where a server records the port it listens on: beside its
// state, because it is as much a part of the network as the state is — every
// invite, every forwarded port and every node's saved address names it.
func PortFile(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "server-port")
}

// RecordedPort is the port the server beside statePath last listened on, or
// zero when none is recorded.
func RecordedPort(statePath string) int {
	b, err := os.ReadFile(PortFile(statePath))
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || p <= 0 || p > 65535 {
		return 0
	}
	return p
}

// RecordPort writes down the port the server beside statePath listens on.
func RecordPort(statePath string, port int) error {
	path := PortFile(statePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strconv.Itoa(port)+"\n"), 0o600)
}

// ListenControl opens the server's port and records which one it is.
//
// An address given explicitly is used as it is. Otherwise the recorded port,
// which never moves once the network exists: the machines already in it hold
// it, and a server that wandered to another port on a busy morning would be
// one none of them could find. Only a server with nothing recorded — a new
// network — picks one: DefaultPort, or the first free one after it.
func ListenControl(statePath, addr string) (net.Listener, int, error) {
	var ln net.Listener
	var err error
	switch recorded := RecordedPort(statePath); {
	case addr != "":
		ln, err = net.Listen("tcp", addr)
	case recorded != 0:
		ln, err = net.Listen("tcp", ":"+strconv.Itoa(recorded))
		if errors.Is(err, syscall.EADDRINUSE) {
			return nil, 0, fmt.Errorf("port %d, where this network's server has always listened and every machine in it looks for it, is taken by something else — free it, or move the network with -addr and new invites", recorded)
		}
	default:
		for p := DefaultPort; p < DefaultPort+portSearch; p++ {
			if ln, err = net.Listen("tcp", ":"+strconv.Itoa(p)); err == nil || !errors.Is(err, syscall.EADDRINUSE) {
				break
			}
		}
		if errors.Is(err, syscall.EADDRINUSE) {
			return nil, 0, fmt.Errorf("no free port from %d to %d for the network's server", DefaultPort, DefaultPort+portSearch-1)
		}
	}
	if err != nil {
		return nil, 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := RecordPort(statePath, port); err != nil {
		ln.Close()
		return nil, 0, fmt.Errorf("record the server's port: %w", err)
	}
	return ln, port, nil
}
