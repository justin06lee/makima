//go:build !windows

package supervise

import (
	"errors"
	"syscall"
)

// detachAttrs puts the child in its own session, so it outlives the shell that
// started it and does not receive a Ctrl-C aimed at the CLI.
func detachAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// terminate asks a process to shut down cleanly.
//
// SIGTERM, never SIGKILL: makimad's shutdown path is what restores the routing
// table, the resolver and the firewall rule, and a machine whose daemon was
// killed outright blackholes mesh addresses until the next reboot.
func terminate(pid int) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// alive reports whether a pid still names a running process.
func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }
