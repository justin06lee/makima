//go:build !unix

package update

import "errors"

// Exec is not available here; the service manager restarts the program.
func Exec(string) error {
	return errors.New("restarting in place is not supported on this platform")
}
