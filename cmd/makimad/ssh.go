package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/sshd"
)

// The built-in SSH server, from the daemon's side.
//
// Off unless switched on, which is the opposite of the inbox and auto-serve,
// and deliberately so. Publishing a port and accepting a file into one
// directory are bounded; handing out a shell is not, and a feature that grants
// one should never be something somebody discovers they had.

// applySSH starts, restarts or stops the SSH server to match the config.
func (n *node) applySSH(ctx context.Context) {
	if n.ssh == nil {
		return
	}

	n.mu.Lock()
	on := n.file.SSH
	sources := append([]string(nil), n.file.SSHKeys...)
	userName := n.file.SSHUser
	machineKey := n.file.MachineKey
	n.mu.Unlock()

	if !on {
		n.ssh.Close()
		return
	}

	account, err := resolveSSHUser(userName)
	if err != nil {
		log.Printf("ssh: %v", err)
		return
	}

	if len(sources) == 0 {
		// The account's own authorized_keys is the obvious default and the one
		// most machines already have. Naming it explicitly — rather than
		// letting the server guess — keeps `makima sshd` able to say exactly
		// where the keys it is honouring came from.
		sources = []string{filepath.Join(account.Home, ".ssh", "authorized_keys")}
	}

	srcs := make([]sshd.Source, 0, len(sources))
	for _, s := range sources {
		srcs = append(srcs, sshd.Source(s))
	}
	if err := n.sshKeys.Set(ctx, srcs); err != nil {
		log.Printf("ssh: %v", err)
	}

	count, _, _ := n.sshKeys.Status()
	if count == 0 {
		// Starting with no keys would be a listening service nobody can use,
		// and the reason is almost always a path that does not exist.
		log.Printf("ssh: not starting — no authorized keys found in %s", strings.Join(sources, ", "))
		n.ssh.Close()
		return
	}

	hostKey, err := sshd.HostKey(machineKey)
	if err != nil {
		log.Printf("ssh: %v", err)
		return
	}

	err = n.ssh.Apply(sshd.Config{
		Addr:       n.meshAddr(),
		HostKey:    hostKey,
		Authorized: n.sshKeys.Allow,
		User:       account,
		Logger:     log.Default(),
	})
	if err != nil {
		log.Printf("ssh: %v", err)
	}
}

// SetSSH switches the SSH server on or off and records the settings.
func (n *node) SetSSH(on bool, keys []string, userName string) error {
	if on {
		// Validated before anything is written, so a typo in a username is
		// reported rather than stored and then quietly ignored on every start.
		if _, err := resolveSSHUser(userName); err != nil {
			return err
		}
	}

	n.mu.Lock()
	n.file.SSH = on
	if keys != nil {
		n.file.SSHKeys = keys
	}
	if userName != "" {
		n.file.SSHUser = userName
	}
	err := conf.Save(n.cfgPath, n.file)
	n.mu.Unlock()

	if err != nil {
		return err
	}

	n.applySSH(context.Background())

	if on {
		if _, active, _, _ := n.ssh.Status(); !active {
			count, _, keyErr := n.sshKeys.Status()
			if count == 0 {
				if keyErr != nil {
					return fmt.Errorf("no authorized keys could be read: %w", keyErr)
				}
				return errors.New("no authorized keys were found, so the server would accept nobody")
			}
			return errors.New("the ssh server did not start; see the daemon's log")
		}
	} else {
		log.Print("ssh: off")
	}
	return nil
}

// resolveSSHUser turns a name into the account sessions will run as.
//
// Empty means the person who started makima — the SUDO_USER behind `makima
// up`, or the daemon's own user when it is not running as root. That is
// almost always the right answer and never needs to be typed.
//
// The account is resolved here rather than taken from the SSH username on
// purpose. A daemon that runs as root and trusts the username it is handed is
// a root shell for anyone holding an authorized key.
func resolveSSHUser(name string) (*sshd.SessionUser, error) {
	if name == "" {
		if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
			name = u
		}
	}

	var u *user.User
	var err error
	if name == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(name)
	}
	if err != nil {
		return nil, fmt.Errorf("no local account %q to run sessions as", name)
	}

	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("account %s has no numeric id", u.Username)
	}

	return &sshd.SessionUser{
		Name:  u.Username,
		UID:   uid,
		GID:   gid,
		Home:  u.HomeDir,
		Shell: loginShell(u),
	}, nil
}
