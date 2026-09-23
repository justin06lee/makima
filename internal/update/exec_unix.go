//go:build unix

package update

import (
	"os"
	"syscall"
)

// Exec replaces this process with the program at path, keeping its arguments
// and environment — and its process ID, so launchd and systemd see the same
// service carry on rather than one that exited.
//
// It returns only on failure.
func Exec(path string) error {
	return syscall.Exec(path, os.Args, os.Environ())
}
