package main

import (
	"errors"
	"flag"
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

// aliasCmd adds `die` to the shell, when asked to.
//
// It is asked to. `makima up` used to do this by itself, which is the kind of
// thing a VPN has no business doing: a shell startup file is somebody's, it is
// read by every shell they open, and editing it as root because they brought a
// tunnel up is a surprise in a file they may not think to look in.
//
// A shell alias rather than a binary called `die` on PATH. A word that generic,
// installed globally, would collide with whatever else a machine has or later
// gains, and would be in the way for every user of the machine rather than the
// one who asked for it. An alias is scoped to the person, visible in a file
// they own, and removable with a text editor.
func aliasCmd(args []string) error {
	fs := flag.NewFlagSet("alias", flag.ExitOnError)
	remove := fs.Bool("remove", false, "take the alias back out")
	if err := fs.Parse(args); err != nil {
		return err
	}

	home, ok := invokingUser()
	if !ok {
		return errors.New("there is no person's shell here to add this to — run it as yourself, not as root")
	}
	rc, ok := shellStartupFile(home)
	if !ok {
		return errors.New("could not work out which startup file your shell reads")
	}

	if *remove {
		removed, err := removeAliasBlock(rc)
		if err != nil {
			return err
		}
		if !removed {
			fmt.Printf("There is no makima block in %s.\n", rc)
			return nil
		}
		fmt.Printf("Removed the makima block from %s. It goes in new shells.\n", rc)
		return nil
	}

	added, err := appendAliasBlock(rc)
	if err != nil {
		return err
	}
	if !added {
		fmt.Printf("%s already has it.\n", rc)
		return nil
	}
	if uid, gid, ok := invokingIDs(); ok {
		// Written as root through sudo, so the file would otherwise stop
		// belonging to the person whose shell reads it.
		_ = os.Chown(rc, uid, gid)
	}

	fmt.Printf("Added to %s:\n\n  %s\n\n", rc, aliasBody)
	fmt.Println("It works in new shells. `makima alias -remove` takes it out again.")
	fmt.Println("Note that `die` is also a common name for a shell function; if you have one,")
	fmt.Println("this shadows it.")
	return nil
}

// offerAlias mentions the shortcut without writing anything.
func offerAlias() {
	if _, ok := invokingUser(); !ok {
		return
	}
	fmt.Println("\nTip: `makima alias` adds `die` to your shell as a shortcut for 'makima down'.")
}

// removeAliasBlock takes the fenced block back out of a startup file.
func removeAliasBlock(rc string) (removed bool, err error) {
	b, err := os.ReadFile(rc)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	text := string(b)
	start := strings.Index(text, aliasBegin)
	if start < 0 {
		return false, nil
	}
	end := strings.Index(text[start:], aliasEnd)
	if end < 0 {
		return false, fmt.Errorf("%s has an unterminated makima block; remove it by hand", rc)
	}
	end += start + len(aliasEnd)
	if end < len(text) && text[end] == '\n' {
		end++
	}
	// The blank line the block was written after goes with it.
	out := strings.TrimSuffix(text[:start], "\n") + text[end:]

	info, err := os.Stat(rc)
	mode := os.FileMode(0o644)
	if err == nil {
		mode = info.Mode().Perm()
	}
	return true, os.WriteFile(rc, []byte(out), mode)
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
	if u := invokerFromEnv(); u != nil {
		return u.HomeDir, u.HomeDir != ""
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

// invokerFromEnv is the person behind this root, by whichever variable says
// so: SUDO_USER from a terminal, PKEXEC_UID from the Linux app's polkit
// prompt, MAKIMA_OWNER from the macOS app's. Nil when nobody is.
func invokerFromEnv() *user.User {
	if sudo := os.Getenv("SUDO_USER"); sudo != "" && sudo != "root" {
		if u, err := user.Lookup(sudo); err == nil {
			return u
		}
	}
	if uid := os.Getenv("PKEXEC_UID"); uid != "" && uid != "0" {
		if u, err := user.LookupId(uid); err == nil {
			return u
		}
	}
	if who := os.Getenv("MAKIMA_OWNER"); who != "" && who != "root" && who != "0" {
		if u, err := user.LookupId(who); err == nil {
			return u
		}
		if u, err := user.Lookup(who); err == nil {
			return u
		}
	}
	return nil
}

// invokingIDs are the numeric ids to hand a file created under sudo back to.
func invokingIDs() (uid, gid int, ok bool) {
	u := invokerFromEnv()
	if u == nil {
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
