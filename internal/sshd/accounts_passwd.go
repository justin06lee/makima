//go:build unix && !darwin

package sshd

import (
	"bufio"
	"os"
	"strings"
)

// The password database, read as a file — which is what it is everywhere but
// macOS. Directory-service accounts are not listed here; a machine whose users
// come from LDAP will show only its local ones, which is the honest answer
// rather than a wrong one.

const passwdFile = "/etc/passwd"

// listAccountNames is every account in the password database.
func listAccountNames() ([]string, error) {
	f, err := os.Open(passwdFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 7 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		names = append(names, fields[0])
	}
	return names, sc.Err()
}

// accountShell is the shell an account logs in with, or "" when unknown.
func accountShell(name string) string {
	f, err := os.Open(passwdFile)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 7 || fields[0] != name {
			continue
		}
		return fields[6]
	}
	return ""
}
