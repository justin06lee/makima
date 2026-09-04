//go:build !unix

package sshd

import "golang.org/x/crypto/ssh"

// Windows has no pty in the sense this server needs, no fork-exec credential
// to drop to, and no /etc/passwd to resolve an account from. Rather than ship
// three quiet approximations, the server refuses to start and says so — the
// rest of makima works there, and `makima ssh` to a machine that does run one
// works from there too.

func supported() error { return ErrUnsupported }

func (s *Server) session(nch ssh.NewChannel, _ Config) {
	_ = nch.Reject(ssh.Prohibited, "makima's ssh server does not run on this platform")
}
