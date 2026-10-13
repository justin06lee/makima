//go:build !windows

package tor

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// unprivileged is who tor runs as when makima is root.
const unprivileged = "nobody"

// prepareDataDir makes tor's data directory, owned by whoever tor will run
// as, and says who that is: nil for "this process's own user".
//
// Tor refuses a data directory that anyone but its own user can read, so the
// directory is 0700 and, under root, handed to the unprivileged user — files
// and all, since a directory a root tor once used is full of root's files.
func prepareDataDir(dir string) (*syscall.Credential, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create tor data directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, nil
	}

	u, err := user.Lookup(unprivileged)
	if err != nil {
		return nil, fmt.Errorf("find the %s user to run tor as: %w", unprivileged, err)
	}
	uid, err := parseID(u.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := parseID(u.Gid)
	if err != nil {
		return nil, err
	}
	err = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, int(uid), int(gid))
	})
	if err != nil {
		return nil, fmt.Errorf("hand tor its data directory: %w", err)
	}
	return &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, nil
}

// parseID reads a uid or gid. macOS's nobody is -2 in /etc/passwd, which is
// what a pure-Go lookup reads, and 4294967294 to the kernel: the same 32 bits.
func parseID(s string) (uint32, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("user id %q: %w", s, err)
	}
	return uint32(n), nil
}

func setCredential(cmd *exec.Cmd, cred *syscall.Credential) {
	if cred == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
}
