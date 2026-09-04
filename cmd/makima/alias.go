package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// The block written into a shell's startup file, fenced so it can be found
// again — to avoid writing it twice, and so somebody who wants it gone can see
// exactly what to delete.
const (
	aliasBegin = "# >>> makima >>>"
	aliasEnd   = "# <<< makima <<<"

	aliasBody = `alias die='sudo makima down'`
)

// installDieAlias adds `die` to the shell, once.
//
// A shell alias rather than a binary called `die` on PATH. A two-letter-ish
// word that generic, installed globally, would collide with whatever else a
// machine has or later gains — and it would be in the way for every user of
// the machine rather than the one who asked for it. An alias is scoped to the
// person, visible in a file they own, and removable with a text editor.
//
// Best effort throughout: a shell config that cannot be written is not a
// reason for `makima up` to fail, because the mesh is already up by then.
func installDieAlias() {
	home, ok := invokingUser()
	if !ok {
		return
	}

	rc, ok := shellStartupFile(home)
	if !ok {
		return
	}

	added, err := appendAliasBlock(rc)
	if err != nil || !added {
		return
	}

	// Written as root through sudo, so the file would otherwise stop belonging
	// to the person whose shell reads it.
	if uid, gid, ok := invokingIDs(); ok {
		_ = os.Chown(rc, uid, gid)
	}

	fmt.Printf("\nAdded `die` to %s as a shortcut for 'makima down'.\n", rc)
	fmt.Printf("It works in new shells. Delete the block marked %q to remove it.\n", "makima")
}

// appendAliasBlock adds the fenced block to a startup file, unless it is
// already there.
//
// Separated from the user and shell lookup around it so the part that must not
// run twice can be tested on a real file. Running `makima up` again is normal,
// and a shell config that grows a duplicate block each time is a mess somebody
// else has to clean up.
func appendAliasBlock(rc string) (added bool, err error) {
	existing, err := os.ReadFile(rc)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if strings.Contains(string(existing), aliasBegin) {
		return false, nil
	}

	f, err := os.OpenFile(rc, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return false, err
	}
	defer f.Close()

	if _, err := f.WriteString("\n" + aliasBegin + "\n" + aliasBody + "\n" + aliasEnd + "\n"); err != nil {
		return false, err
	}
	return true, nil
}

// invokingUser is the person who ran the command, not the root it became.
func invokingUser() (home string, ok bool) {
	if sudo := os.Getenv("SUDO_USER"); sudo != "" && sudo != "root" {
		u, err := user.Lookup(sudo)
		if err != nil {
			return "", false
		}
		return u.HomeDir, true
	}

	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		return "", false
	}
	// Running as root outright, with no sudo behind it: there is no person's
	// shell to add this to, and writing to root's is not useful.
	if u.Uid == "0" {
		return "", false
	}
	return u.HomeDir, true
}

// invokingIDs are the numeric ids to hand a file created under sudo back to.
func invokingIDs() (uid, gid int, ok bool) {
	sudo := os.Getenv("SUDO_USER")
	if sudo == "" || sudo == "root" {
		return 0, 0, false
	}
	u, err := user.Lookup(sudo)
	if err != nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(u.Uid, "%d", &uid); err != nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(u.Gid, "%d", &gid); err != nil {
		return 0, 0, false
	}
	return uid, gid, true
}

// shellStartupFile picks the file the person's shell actually reads.
//
// By what exists on disk rather than by $SHELL, because under sudo $SHELL is
// often root's and the answer would be wrong on exactly the path this is
// always taken from.
func shellStartupFile(home string) (string, bool) {
	candidates := []string{".zshrc", ".bashrc", ".bash_profile", ".profile"}
	for _, c := range candidates {
		p := filepath.Join(home, c)
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}
