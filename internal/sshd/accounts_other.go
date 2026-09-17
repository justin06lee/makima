//go:build !unix

package sshd

import "errors"

// The server does not run here (see session_other.go), so neither does
// anything that would resolve an account for it.

type SystemAccounts struct{}

func (SystemAccounts) Lookup(string) (*SessionUser, error) { return nil, ErrUnsupported }
func (SystemAccounts) List() ([]*SessionUser, error)       { return nil, ErrUnsupported }
func (SystemAccounts) Keys(*SessionUser) ([]AuthorizedKey, error) {
	return nil, errors.ErrUnsupported
}
