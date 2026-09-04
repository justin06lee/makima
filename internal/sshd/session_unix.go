//go:build unix

package sshd

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// supported reports whether sessions can run here. On unix they always can.
func supported() error { return nil }

// session runs one SSH session channel: a shell, or one command.
//
// Everything a client can influence is bounded before it reaches a process.
// The account is chosen on this machine, the environment is rebuilt rather
// than inherited from the request, and the command — when there is one — is
// handed to the account's own shell rather than parsed here.
func (s *Server) session(nch ssh.NewChannel, cfg Config) {
	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	var (
		mu      sync.Mutex
		ptyReq  *ptyRequest
		started bool
	)

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			mu.Lock()
			if started {
				mu.Unlock()
				req.Reply(false, nil)
				continue
			}
			p, err := parsePTYRequest(req.Payload)
			if err == nil {
				ptyReq = p
			}
			mu.Unlock()
			req.Reply(err == nil, nil)

		case "window-change":
			mu.Lock()
			p := ptyReq
			mu.Unlock()
			if p == nil {
				req.Reply(false, nil)
				continue
			}
			if w, h, err := parseWindowChange(req.Payload); err == nil {
				p.resize(w, h)
			}
			req.Reply(true, nil)

		case "shell", "exec":
			mu.Lock()
			if started {
				mu.Unlock()
				req.Reply(false, nil)
				continue
			}
			started = true
			p := ptyReq
			mu.Unlock()

			command := ""
			if req.Type == "exec" {
				command, err = parseString(req.Payload)
				if err != nil {
					req.Reply(false, nil)
					continue
				}
			}
			req.Reply(true, nil)

			code := s.run(ch, cfg, p, command)
			sendExitStatus(ch, code)
			ch.Close()

		case "subsystem":
			// sftp is the one people will try. Saying so plainly beats a
			// generic failure, and `makima cp` is the answer.
			name, _ := parseString(req.Payload)
			if name == "sftp" {
				fmt.Fprintln(ch.Stderr(), "makima's ssh server has no sftp subsystem — use 'makima cp' to move files")
			}
			req.Reply(false, nil)

		case "env":
			// Ignored, deliberately. An environment supplied by whoever
			// connected is the classic way to smuggle LD_PRELOAD or PATH into
			// a process running as somebody else, and nothing here needs it.
			req.Reply(false, nil)

		default:
			req.Reply(false, nil)
		}
	}
}

// run starts the process and copies streams until it exits.
func (s *Server) run(ch ssh.Channel, cfg Config, p *ptyRequest, command string) int {
	u := cfg.User

	shell := u.Shell
	if shell == "" {
		shell = "/bin/sh"
	}

	var cmd *exec.Cmd
	if command == "" {
		cmd = exec.Command(shell, "-l")
	} else {
		// Handed to the shell rather than split here. Clients send a single
		// string and expect shell semantics — quoting, pipes, redirection —
		// and a half-implemented parser would differ from every other sshd in
		// ways nobody could predict.
		cmd = exec.Command(shell, "-c", command)
	}

	cmd.Dir = u.Home
	cmd.Env = environment(u, p)
	if credential := credentialFor(u); credential != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	}

	if p != nil {
		return s.runPTY(ch, cmd, p)
	}
	return s.runPipes(ch, cmd)
}

// runPTY runs the process on a pseudo-terminal.
//
// Needed for anything interactive: without one there is no job control, no
// line editing, and no program that asks "am I on a terminal" gets the right
// answer — which is most of them.
func (s *Server) runPTY(ch ssh.Channel, cmd *exec.Cmd, p *ptyRequest) int {
	f, err := pty.StartWithSize(cmd, p.winsize())
	if err != nil {
		fmt.Fprintf(ch.Stderr(), "makima: could not start a shell: %v\n", err)
		return 1
	}
	defer f.Close()

	p.attach(f)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Into the terminal. An error here means the client hung up.
		_, _ = io.Copy(f, ch)
	}()

	// Out of the terminal. This is the one that decides when we are done: a
	// pty read returns EIO once the child has exited and closed the far side.
	_, _ = io.Copy(ch, f)

	code := wait(cmd)

	// The input copier is parked on a read from the client, which will not
	// return until the client closes. Closing the pty unblocks the write side
	// so the goroutine is not leaked for the life of the connection.
	f.Close()
	wg.Wait()
	return code
}

// runPipes runs the process with plain pipes, for a non-interactive command.
func (s *Server) runPipes(ch ssh.Channel, cmd *exec.Cmd) int {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 1
	}
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(ch.Stderr(), "makima: %v\n", err)
		return 1
	}

	go func() {
		_, _ = io.Copy(stdin, ch)
		// Half-close, so a command reading to EOF — `cat`, `sort`, `wc` —
		// finishes rather than hanging once the client stops sending.
		stdin.Close()
	}()

	return wait(cmd)
}

// wait collects the exit status, translating a signal into the convention
// shells use so `echo $?` says what it says everywhere else.
func wait(cmd *exec.Cmd) int {
	err := cmd.Wait()
	if err == nil {
		return 0
	}

	var ee *exec.ExitError
	if !asExitError(err, &ee) {
		return 1
	}
	if status, ok := ee.Sys().(syscall.WaitStatus); ok {
		if status.Signaled() {
			return 128 + int(status.Signal())
		}
		return status.ExitStatus()
	}
	return ee.ExitCode()
}

// credentialFor is how a root daemon drops to the session account.
//
// Nil when the daemon is already that user, which is the whole check: setting
// a credential to your own uid is a no-op that can still fail, and failing
// would refuse a session for no reason.
func credentialFor(u *SessionUser) *syscall.Credential {
	if u.UID < 0 || os.Geteuid() != 0 {
		return nil
	}
	if u.UID == os.Geteuid() && u.GID == os.Getegid() {
		return nil
	}
	return &syscall.Credential{Uid: uint32(u.UID), Gid: uint32(u.GID)}
}

// environment builds the environment a session starts with.
//
// Constructed rather than inherited. The daemon's own environment belongs to
// root and to whatever started it, and passing it through would leak both into
// a shell running as somebody else.
func environment(u *SessionUser, p *ptyRequest) []string {
	shell := u.Shell
	if shell == "" {
		shell = "/bin/sh"
	}

	env := []string{
		"USER=" + u.Name,
		"LOGNAME=" + u.Name,
		"HOME=" + u.Home,
		"SHELL=" + shell,
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"MAKIMA_SSH=1",
	}
	if p != nil && p.term != "" {
		// The one thing the client is allowed to choose, because without it
		// nothing draws correctly, and a terminal name reaches nothing more
		// dangerous than terminfo.
		env = append(env, "TERM="+sanitiseTerm(p.term))
	}
	return env
}

// sanitiseTerm keeps a client-supplied TERM to the shape a real one has.
func sanitiseTerm(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		}
		return -1
	}, s)
}

// sendExitStatus tells the client what the process returned, which is what
// makes `makima ssh host false` exit non-zero locally.
func sendExitStatus(ch ssh.Channel, code int) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], uint32(code))
	_, _ = ch.SendRequest("exit-status", false, payload[:])
}
