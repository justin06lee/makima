package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// needsRoot are the commands that only read, and still need root to do it:
// the node's configuration is root's alone, and so is the daemon's own socket.
// They ask sudo on the way in, as the commands that change things always have
// — typing sudo in front of makima is never the person's job.
var needsRoot = map[string]bool{
	"status":   true,
	"show":     true,
	"doctor":   true,
	"firewall": true,
	"sshd":     true,
	"peer":     true,
	"init":     true,
}

// trustedCopy is root's own copy of makima, which the desktop app keeps.
//
// Once somebody has said yes to the app, sudo lets their account run that
// copy's everyday verbs without a password — desktop/src-tauri/src/privileged.rs
// writes the rule. A terminal gets the same courtesy by running that copy, but
// only when it is this very build, or the command that ran would not be the
// one that was typed.
const trustedCopy = "/Library/PrivilegedHelperTools/makima/makima"

// mustBeRoot re-runs this command under sudo rather than telling somebody to.
//
// "Permission denied, try again with sudo" is a step, and every step is a place
// to stop. The daemon genuinely needs root — it creates a network interface and
// edits the routing table — so the only question is who types the word, and it
// may as well be the program. On success it does not return: the command ran
// as root, and this process exits with its status.
func mustBeRoot() error {
	if os.Geteuid() == 0 {
		return nil
	}

	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return errors.New("this needs root, and there is no sudo here to ask for it")
	}

	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}
	args := os.Args[1:]

	if sameBuild(self, trustedCopy) && quiet(sudo, append([]string{"-n", "-l", trustedCopy}, args...)...) {
		replace(exec.Command(sudo, append([]string{"-n", trustedCopy}, args...)...))
	}

	// Said only when sudo is about to ask. A password prompt out of nowhere
	// reads as something gone wrong; a line before every command is noise.
	if !quiet(sudo, "-n", "true") {
		fmt.Fprintln(os.Stderr, "This needs root — asking sudo.")
	}
	replace(exec.Command(sudo, append([]string{self}, args...)...))
	return nil
}

// replace runs cmd in this process's place and exits with its status.
func replace(cmd *exec.Cmd) {
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		os.Exit(0)
	case errors.As(err, &ee):
		os.Exit(ee.ExitCode())
	}
	fmt.Fprintf(os.Stderr, "makima: %v\n", err)
	os.Exit(1)
}

// quiet runs a command with nothing attached and says whether it succeeded.
func quiet(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}

// sameBuild says two paths hold the same program.
func sameBuild(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 != nil || err2 != nil {
		return false
	}
	if ra == rb {
		return true
	}
	x, err1 := os.ReadFile(ra)
	y, err2 := os.ReadFile(rb)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// atTerminal says a person is there to answer sudo.
func atTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
