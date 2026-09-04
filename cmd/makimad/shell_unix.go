//go:build unix

package main

import (
	"bufio"
	"os"
	"os/user"
	"strings"
)

// loginShell finds the shell an account logs in with.
//
// os/user does not report it — the standard library's User has no Shell field
// — so it comes from the passwd database directly. Falling back to /bin/sh,
// which is the one shell that is always there.
func loginShell(u *user.User) string {
	if s := shellFromPasswd(u.Username); s != "" {
		return s
	}
	return "/bin/sh"
}

// shellFromPasswd reads /etc/passwd.
//
// Enough on Linux and on macOS for local accounts, which is what this server
// runs sessions as. A directory-service account will fall back to /bin/sh,
// which works — it is a worse shell, not a broken one.
func shellFromPasswd(username string) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 || fields[0] != username {
			continue
		}
		if shell := fields[6]; shell != "" {
			return shell
		}
	}
	return ""
}
