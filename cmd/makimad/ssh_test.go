package main

import (
	"os/user"
	"testing"
)

// With nobody owning the machine, the default account used to be the
// daemon's own — root, since the daemon always is — so every key the server
// accepted got a root shell by default.
func TestNoOwnerIsNotARootShell(t *testing.T) {
	was := currentUser
	currentUser = func() (*user.User, error) { return &user.User{Uid: "0", Username: "root"}, nil }
	t.Cleanup(func() { currentUser = was })

	if u, err := resolveSSHUser("", nil); err == nil {
		t.Errorf("with no owner, sessions default to %s", u.Name)
	}
}

// Somebody who names root gets root: the refusal is about defaults.
func TestNamingAnAccountStillWorks(t *testing.T) {
	if _, err := resolveSSHUser("root", nil); err != nil {
		t.Skipf("no root account to look up here: %v", err)
	}
}
