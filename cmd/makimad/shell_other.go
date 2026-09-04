//go:build !unix

package main

import "os/user"

// The SSH server does not run on this platform, so the shell it would use
// never comes up. Present so the daemon still builds everywhere.
func loginShell(*user.User) string { return "" }
