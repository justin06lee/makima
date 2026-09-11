package migrate

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SSH runs commands on other machines with the person's own ssh client.
//
// The system client rather than a Go one, because it is the one that already
// works: it has their keys, their agent, their ~/.ssh/config, and — the reason
// that settles it — it speaks to Tailscale SSH, which is how a lot of tailnets
// reach their machines with no keys at all.
type SSH struct {
	bin string

	// knownHosts is a file this process owns. Host keys Tailscale published
	// are written into it and required; a machine whose keys are not known
	// is accepted on first use into it and nowhere else. The person's own
	// known_hosts is read but never written.
	knownHosts string

	mu     sync.Mutex
	pinned map[string]bool
}

// Shell is what the migration needs from SSH, so the run can be exercised
// against machines that are not there.
type Shell interface {
	Pin(addr string, keys []string) error
	Run(ctx context.Context, t Target, script string, stdin []byte, onAuth func(string)) (string, error)
}

// ErrDenied means the machine answered and refused the login. Tailscale SSH
// refuses a user its policy does not allow by closing the connection without
// a word, which ssh reports as nothing but status 255 — so that is a refusal
// too.
var ErrDenied = errors.New("the machine refused the login")

// ErrUnreachable means there was nobody to ask: trying another user is pointless.
var ErrUnreachable = errors.New("it did not answer")

// authURL is how Tailscale SSH asks for a browser check before it lets a
// session through. The session waits for it rather than failing.
var authURL = regexp.MustCompile(`https://login\.tailscale\.com/\S+`)

// NewSSH finds ssh and makes the known-hosts file.
func NewSSH() (*SSH, error) {
	bin, err := exec.LookPath("ssh")
	if err != nil {
		bin = "/usr/bin/ssh"
		if _, serr := os.Stat(bin); serr != nil {
			return nil, errors.New("there is no ssh client on this machine")
		}
	}
	f, err := os.CreateTemp("", "makima-migrate-known-hosts-")
	if err != nil {
		return nil, err
	}
	f.Close()
	return &SSH{bin: bin, knownHosts: f.Name(), pinned: map[string]bool{}}, nil
}

// Close removes the known-hosts file.
func (s *SSH) Close() {
	if s != nil && s.knownHosts != "" {
		os.Remove(s.knownHosts)
	}
}

// Pin records the host keys an address must present.
func (s *SSH) Pin(addr string, keys []string) error {
	if len(keys) == 0 || addr == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pinned[addr] {
		return nil
	}
	f, err := os.OpenFile(s.knownHosts, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, k := range keys {
		// Each published key is "type base64", which is a known_hosts line
		// once the host is put in front of it.
		k = strings.TrimSpace(k)
		if k == "" || strings.ContainsAny(k, "\n\r") {
			continue
		}
		if _, err := fmt.Fprintf(f, "%s %s\n", knownHostsName(addr), k); err != nil {
			return err
		}
	}
	s.pinned[addr] = true
	return nil
}

func knownHostsName(addr string) string {
	if strings.Contains(addr, ":") {
		return "[" + addr + "]"
	}
	return addr
}

// Target is one machine, at one address, as one user.
type Target struct {
	Addr string
	Port int    // 0 is ssh's default
	User string // "" is ssh's default, which honours ~/.ssh/config
}

func (t Target) String() string {
	s := t.Addr
	if t.User != "" {
		s = t.User + "@" + s
	}
	if t.Port != 0 {
		s += ":" + strconv.Itoa(t.Port)
	}
	return s
}

// Run executes a shell script on a machine and returns what it printed.
//
// onAuth is called with the URL if Tailscale SSH stops to ask for a browser
// check. The session keeps waiting — approving it lets the same session
// through — so the caller's context decides how long that wait may be.
func (s *SSH) Run(ctx context.Context, t Target, script string, stdin []byte, onAuth func(string)) (string, error) {
	// Published keys are OpenSSH's, or Tailscale SSH's — which serves the
	// same ones — so they are required on port 22 only. makima's own SSH
	// server, on its own port, has a key of its own.
	s.mu.Lock()
	pinned := s.pinned[t.Addr] && (t.Port == 0 || t.Port == 22)
	s.mu.Unlock()

	args := []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=8",
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=3",
		// Not LogLevel=ERROR: Tailscale SSH's browser check arrives as an
		// authentication banner, and banners are only shown at INFO.
	}
	if pinned {
		args = append(args,
			"-o", "StrictHostKeyChecking=yes",
			"-o", "UserKnownHostsFile="+s.knownHosts)
	} else {
		args = append(args,
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "UserKnownHostsFile="+s.knownHosts+" ~/.ssh/known_hosts")
	}
	if t.Port != 0 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	if t.User != "" {
		args = append(args, "-l", t.User)
	}
	args = append(args, t.Addr, "--", "sh -c "+ShellQuote(script))

	cmd := exec.CommandContext(ctx, s.bin, args...)
	cmd.WaitDelay = 2 * time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}

	var stderr strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(errPipe)
		for sc.Scan() {
			line := sc.Text()
			if u := authURL.FindString(line); u != "" && onAuth != nil {
				onAuth(u)
				continue
			}
			stderr.WriteString(line)
			stderr.WriteByte('\n')
		}
		io.Copy(io.Discard, errPipe)
	}()
	<-done
	err = cmd.Wait()

	if err != nil {
		if ctx.Err() != nil {
			return stdout.String(), fmt.Errorf("%s did not answer in time", t.Addr)
		}
		return stdout.String(), sshError(err, stderr.String())
	}
	return stdout.String(), nil
}

// sshError turns ssh's failure into one sentence about the machine.
func sshError(err error, stderr string) error {
	msg := lastLine(stderr)
	switch {
	case strings.Contains(stderr, "Permission denied"):
		return ErrDenied
	case strings.Contains(stderr, "Host key verification failed"),
		strings.Contains(stderr, "REMOTE HOST IDENTIFICATION HAS CHANGED"):
		return fmt.Errorf("%w: its SSH host key is not the one Tailscale lists for it, so it was not trusted", ErrUnreachable)
	case strings.Contains(stderr, "Connection timed out"),
		strings.Contains(stderr, "Operation timed out"),
		strings.Contains(stderr, "No route to host"),
		strings.Contains(stderr, "Network is unreachable"),
		strings.Contains(stderr, "Could not resolve"):
		return ErrUnreachable
	case strings.Contains(stderr, "Connection refused"):
		return fmt.Errorf("%w: nothing is accepting SSH on it — turn on Tailscale SSH there (tailscale set --ssh), or start sshd", ErrUnreachable)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() != 255 {
		// The command ran and failed; its own words are the useful part.
		if msg == "" {
			return fmt.Errorf("it exited with status %d", ee.ExitCode())
		}
		return errors.New(msg)
	}
	if msg != "" {
		return errors.New(msg)
	}
	return ErrDenied
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

// ShellQuote quotes one word for a POSIX shell.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
