//go:build !darwin && !linux

package portmap

// DefaultRoute is unimplemented elsewhere.
//
// Returning the sentinel rather than an OS-specific error keeps the caller's
// handling identical: a node that cannot find its gateway simply has no port
// mapping, which is the same situation as a router that refuses one, and the
// relay covers both.
func DefaultRoute() (Route, error) { return Route{}, ErrNoGateway }
