package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/ssh"
)

// ed25519Keys mints a client keypair for the tests.
func ed25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// asExit is errors.As for an SSH exit error, named so the test reads as one
// thought.
func asExit(err error, target **ssh.ExitError) bool { return errors.As(err, target) }
