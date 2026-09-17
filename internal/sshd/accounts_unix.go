//go:build unix

package sshd

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// SystemAccounts is the machine's own password database.
type SystemAccounts struct{}

// Lookup resolves one local account a session could run as.
func (SystemAccounts) Lookup(name string) (*SessionUser, error) {
	if name == "" {
		return nil, errors.New("sshd: no account named")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("sshd: no local account %q", name)
	}
	return sessionUser(u)
}

// List is every local account somebody could log in as.
func (SystemAccounts) List() ([]*SessionUser, error) {
	names, err := listAccountNames()
	if err != nil {
		return nil, err
	}

	var out []*SessionUser
	for _, name := range names {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		su, err := sessionUser(u)
		if err != nil {
			continue
		}
		out = append(out, su)
	}
	return out, nil
}

// sessionUser fills in everything a session needs to run as an account, and
// refuses one nobody could log in as.
func sessionUser(u *user.User) (*SessionUser, error) {
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("sshd: account %s has no numeric id", u.Username)
	}

	shell := accountShell(u.Username)
	if !canLogIn(shell) {
		return nil, fmt.Errorf("sshd: %s is not an account anybody logs in as", u.Username)
	}
	if fi, err := os.Stat(u.HomeDir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("sshd: %s has no home directory", u.Username)
	}

	// The account's other groups, which are how sudo, docker, wheel and the
	// rest work. Without them a session is the account in name and in nothing
	// else — and root's groups, which the daemon has, must not be what a
	// session inherits instead.
	var groups []int
	if ids, err := u.GroupIds(); err == nil {
		for _, id := range ids {
			if n, err := strconv.Atoi(id); err == nil && n != gid {
				groups = append(groups, n)
			}
		}
	}

	return &SessionUser{
		Name:   u.Username,
		UID:    uid,
		GID:    gid,
		Groups: groups,
		Home:   u.HomeDir,
		Shell:  shell,
	}, nil
}

// authorizedKeyFiles are the files OpenSSH reads by default, in its order.
var authorizedKeyFiles = []string{"authorized_keys", "authorized_keys2"}

// Keys reads an account's own authorized_keys.
//
// The permission checks are OpenSSH's StrictModes, and they are the reason
// this is worth doing carefully: a file anybody on the machine can write is a
// list of who may become this account that anybody on the machine may add
// themselves to. A home directory anybody can write is the same thing one step
// removed, since they could replace .ssh outright.
//
// A symlink is refused rather than followed, for the same reason: what it
// points at is not necessarily what its owner can see.
func (SystemAccounts) Keys(u *SessionUser) ([]AuthorizedKey, error) {
	if err := ownedAndPrivate(u.Home, u.UID); err != nil {
		return nil, err
	}
	dir := filepath.Join(u.Home, ".ssh")
	if err := ownedAndPrivate(dir, u.UID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var out []AuthorizedKey
	for _, name := range authorizedKeyFiles {
		path := filepath.Join(dir, name)
		if err := ownedAndPrivate(path, u.UID); err != nil {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		keys, err := ParseAuthorizedKeys(b)
		if err != nil {
			continue
		}
		out = append(out, keys...)
	}
	return out, nil
}

// ownedAndPrivate is StrictModes for one path: it exists, it is not a symlink,
// it belongs to this account or to root, and nobody else can write it.
func ownedAndPrivate(path string, uid int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sshd: %s is a symlink, so it is not trusted", path)
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("sshd: cannot check who owns %s", path)
	}
	if int(st.Uid) != uid && st.Uid != 0 {
		return fmt.Errorf("sshd: %s belongs to uid %d, not to %d or root", path, st.Uid, uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("sshd: %s is writable by others (%04o)", path, fi.Mode().Perm())
	}
	return nil
}
