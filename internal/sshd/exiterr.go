package sshd

import (
	"errors"
	"os/exec"
)

// asExitError is errors.As with a name, so the exit-status path reads as one
// thought rather than three lines of type assertion.
func asExitError(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}
