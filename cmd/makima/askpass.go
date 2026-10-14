package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// makima as ssh's password prompt.
//
// ssh asks "huiyunlee@makima-3f9a1c0e5b2d7a64's password:", naming the
// machine by the alias its host key is filed under (see hostKeyAlias) — or by
// its mesh address, without one. Either reads like an ID, and makes an
// ordinary password prompt look like something has gone wrong. ssh lets
// another program do the asking (SSH_ASKPASS), and for `makima ssh` makima is
// that program: it asks "huiyunlee's password:" at the terminal, with the
// echo off as ssh would, and hands back exactly what was typed. Nothing is
// kept, and nothing but the prompt is changed.

// askpassEnv marks a run of makima as ssh's prompt rather than a command.
const askpassEnv = "MAKIMA_ASKPASS"

// askpassEnviron is what makes ssh ask through makima: nothing where there
// is no terminal device to ask at, or no path to this program to give it.
// ssh before 8.4 ignores SSH_ASKPASS_REQUIRE and asks for itself, as before.
func askpassEnviron() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil
	}
	return []string{"SSH_ASKPASS=" + self, "SSH_ASKPASS_REQUIRE=force", askpassEnv + "=1"}
}

// isAskpass reports whether this run is ssh asking for something: ssh runs
// the program with the prompt as its one argument, and the environment says
// it was makima that set ssh up to.
func isAskpass() bool {
	return os.Getenv(askpassEnv) == "1" && len(os.Args) == 2
}

// askpass asks at the terminal and writes the answer to stdout, where ssh
// reads it. Its exit status is ssh's yes or no.
func askpass(prompt string) int {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return 1
	}
	defer tty.Close()

	switch os.Getenv("SSH_ASKPASS_PROMPT") {
	case "none":
		// Something to show, with nothing to answer.
		fmt.Fprintln(tty, prompt)
		return 0
	case "confirm":
		fmt.Fprint(tty, strings.TrimRight(prompt, " ")+" ")
		line, _ := bufio.NewReader(tty).ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return 0
		}
		return 1
	}

	fmt.Fprint(tty, plainPrompt(prompt))

	// ^C while the echo is off must not leave the terminal that way.
	fd := int(tty.Fd())
	if state, err := term.GetState(fd); err == nil {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		go func() {
			<-sig
			term.Restore(fd, state)
			fmt.Fprintln(tty)
			os.Exit(1)
		}()
	}

	secret, err := term.ReadPassword(fd)
	fmt.Fprintln(tty)
	if err != nil {
		return 1
	}
	os.Stdout.Write(append(secret, '\n'))
	return 0
}

// plainPrompt is ssh's prompt with the machine taken out of it — whose
// password it is, and nothing that reads like an ID:
//
//	huiyunlee@makima-3f9a…'s password:     huiyunlee's password:
//	(huiyunlee@makima-3f9a…) Password:     huiyunlee's password:   how a Mac asks
//	(midna@10.77.0.1) Verification code:   Verification code:
//	anything else                          as it was
func plainPrompt(p string) string {
	s := strings.TrimRight(p, " ")

	if user, rest, ok := strings.Cut(s, "@"); ok && user != "" &&
		!strings.ContainsAny(user, " ()") && strings.HasSuffix(rest, "'s password:") {
		return user + "'s password: "
	}

	// Keyboard-interactive: ssh puts "(user@host) " before what the server
	// asked, which on a Mac and most Linux machines is "Password:".
	if inner, ok := strings.CutPrefix(s, "("); ok {
		if who, asked, ok := strings.Cut(inner, ") "); ok && strings.Contains(who, "@") {
			user, _, _ := strings.Cut(who, "@")
			if strings.EqualFold(strings.TrimSpace(asked), "password:") && user != "" {
				return user + "'s password: "
			}
			return asked + " "
		}
	}
	return p
}
