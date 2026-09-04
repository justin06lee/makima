//go:build !linux && !darwin

package localports

import "errors"

// listening has no implementation on this platform.
//
// Returning an error rather than an empty slice matters: callers treat an
// error as "no information" and leave what they published alone, whereas an
// empty slice means "nothing is running here" and would withdraw every
// automatically published service.
func listening() ([]Listener, error) {
	return nil, errors.New("localports: not supported on this platform")
}
