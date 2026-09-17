package sshd

import (
	"os/exec"
	"strings"
	"time"
)

// macOS keeps accounts in Directory Services rather than /etc/passwd, which
// holds only the system's own. dscl is the way to read it, and the only reason
// this file exists.

// dsclTimeout bounds a directory lookup. Local reads are instant; a machine
// bound to a network directory can be slow, and an SSH handshake should not
// wait on it.
const dsclTimeout = 5 * time.Second

func dscl(args ...string) (string, bool) {
	cmd := exec.Command("dscl", args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.Output()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(dsclTimeout):
		_ = cmd.Process.Kill()
		return "", false
	}
	if err != nil {
		return "", false
	}
	return string(out), true
}

// listAccountNames is every account with a login shell, which on a Mac is the
// cheapest way to skip the several dozen underscore-prefixed daemon accounts.
func listAccountNames() ([]string, error) {
	out, ok := dscl(".", "-list", "/Users", "UserShell")
	if !ok {
		return nil, nil
	}

	var names []string
	for _, line := range strings.Split(out, "\n") {
		name, shell, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found || name == "" || strings.HasPrefix(name, "_") {
			continue
		}
		if canLogIn(strings.TrimSpace(shell)) {
			names = append(names, name)
		}
	}
	return names, nil
}

// accountShell is the shell an account logs in with, or "" when unknown.
func accountShell(name string) string {
	out, ok := dscl(".", "-read", "/Users/"+name, "UserShell")
	if !ok {
		return ""
	}
	_, shell, found := strings.Cut(strings.TrimSpace(out), ":")
	if !found {
		return ""
	}
	return strings.TrimSpace(shell)
}
