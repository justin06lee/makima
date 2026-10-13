// Package tor runs a private Tor for makima: to publish the control plane as
// an onion service, and to reach it at its onion address from anywhere.
//
// An onion service is the one way to make a machine reachable that asks
// nothing of the network it sits on. The machine connects out to Tor, as
// anything can from behind any router — carrier-grade NAT included — and is
// found by an address derived from its own key. No port forward, no public
// address, no name to keep pointed at a home connection, and no company in
// the path. That is the job DuckDNS and a router's port forward used to do
// between them, and could not do at all behind CGNAT.
//
// Only the coordination plane goes over Tor: check-ins, the netmap, the
// setting-up of direct paths, and the relay as a last resort. WireGuard
// traffic still goes machine to machine once a direct path is punched. Tor is
// slow and carries only TCP, which suits a long poll and would not suit a
// tunnel.
//
// Each process that needs Tor runs its own, with its own data directory: a
// child process, never the system's Tor service, configured entirely from the
// command line so no torrc on the machine changes what it does. It dies with
// the process that started it. When that process is root, Tor is started as
// an unprivileged user instead; it parses the internet's input, and has no
// need to do that as root.
package tor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrNotInstalled is a machine with no tor binary to run.
var ErrNotInstalled = errors.New("tor is not installed — install it (brew install tor, or apt install tor) to reach this network from anywhere")

// searchPath is where tor is looked for beyond $PATH: a daemon started by
// launchd or systemd has a bare $PATH that does not include Homebrew.
var searchPath = []string{
	"/opt/homebrew/bin/tor",
	"/usr/local/bin/tor",
	"/usr/bin/tor",
	"/usr/sbin/tor",
}

// Find locates the tor binary: $MAKIMA_TOR, one beside this executable (a
// bundled copy), $PATH, then the usual install locations.
func Find() (string, error) {
	if p := os.Getenv("MAKIMA_TOR"); p != "" {
		if isExecutable(p) {
			return p, nil
		}
		return "", fmt.Errorf("MAKIMA_TOR=%s is not an executable", p)
	}
	candidates := []string{}
	if self, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(self), "tor"))
	}
	if p, err := exec.LookPath("tor"); err == nil {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, searchPath...)
	for _, p := range candidates {
		if isExecutable(p) {
			return p, nil
		}
	}
	return "", ErrNotInstalled
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}

// Tor is one running tor process and the control connection that owns it.
type Tor struct {
	cmd   *exec.Cmd
	ctl   *controlConn
	socks string // where its SOCKS port listens, 127.0.0.1:port
	log   *log.Logger

	done    chan struct{} // closed when the process exits
	exitErr error         // why, once done is closed

	closeOnce sync.Once
}

// startTimeout bounds tor coming up far enough to be controlled — not joining
// the network, which is slower and waited for separately.
const startTimeout = 30 * time.Second

// Start runs a private tor with its state in dataDir.
func Start(dataDir string, logger *log.Logger) (*Tor, error) {
	if logger == nil {
		logger = log.Default()
	}
	bin, err := Find()
	if err != nil {
		return nil, err
	}

	// An empty torrc of its own: tor will not take /dev/null for one, and
	// without -f it would read the system's.
	torrc := filepath.Join(dataDir, "torrc")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create tor data directory: %w", err)
	}
	if err := os.WriteFile(torrc, []byte("# makima configures this tor from its command line.\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write tor's torrc: %w", err)
	}
	cred, err := prepareDataDir(dataDir)
	if err != nil {
		return nil, err
	}
	portFile := filepath.Join(dataDir, "control-port")
	_ = os.Remove(portFile)

	args := []string{
		// What this tor does is what is written here, and nothing an
		// operator put in /etc/tor/torrc for the system's tor.
		"-f", torrc, "--defaults-torrc", torrc,
		"--DataDirectory", dataDir,
		"--ClientOnly", "1",
		"--SocksPort", "auto ExtendedErrors",
		"--ControlPort", "auto",
		"--ControlPortWriteToFile", portFile,
		"--CookieAuthentication", "1",
		// Tor watches this process and exits when it does, so a daemon that
		// is killed outright does not leave a tor behind.
		"--__OwningControllerProcess", strconv.Itoa(os.Getpid()),
		"--AvoidDiskWrites", "1",
		"--Log", "notice stdout",
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = dataDir
	cmd.Env = []string{"HOME=" + dataDir, "PATH=/usr/bin:/bin"}
	setCredential(cmd, cred)

	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tor: %w", err)
	}

	t := &Tor{cmd: cmd, log: logger, done: make(chan struct{})}
	go t.relayLog(out)
	go func() {
		t.exitErr = cmd.Wait()
		close(t.done)
	}()

	if err := t.attach(portFile, filepath.Join(dataDir, "control_auth_cookie")); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

// attach waits for tor to say where its control port is, takes ownership of
// it, and finds the SOCKS port.
func (t *Tor) attach(portFile, cookieFile string) error {
	deadline := time.Now().Add(startTimeout)
	var addr string
	for {
		if b, err := os.ReadFile(portFile); err == nil {
			if a, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "PORT="); ok {
				addr = a
				break
			}
		}
		select {
		case <-t.done:
			return fmt.Errorf("tor exited as it started: %v", t.exitErr)
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("tor did not open its control port")
		}
	}

	ctl, err := dialControl(addr)
	if err != nil {
		return err
	}
	t.ctl = ctl

	cookie, err := os.ReadFile(cookieFile)
	if err != nil {
		return fmt.Errorf("read tor's control cookie: %w", err)
	}
	if err := ctl.authenticate(cookie); err != nil {
		return fmt.Errorf("authenticate to tor: %w", err)
	}
	// Tor exits the moment this connection closes, as well as when this
	// process does — however this process goes, its tor goes with it.
	if _, err := ctl.cmd("TAKEOWNERSHIP"); err != nil {
		return fmt.Errorf("take ownership of tor: %w", err)
	}

	listeners, err := ctl.getinfo("net/listeners/socks")
	if err != nil {
		return err
	}
	fields := strings.Fields(listeners)
	if len(fields) == 0 {
		return errors.New("tor opened no SOCKS port")
	}
	t.socks = unquote(fields[0])
	return nil
}

// relayLog passes on what tor says that someone might need: warnings, errors,
// and the moment it is connected. The rest is tor narrating its bootstrap.
func (t *Tor) relayLog(r io.Reader) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		switch {
		case strings.Contains(line, "[warn]"), strings.Contains(line, "[err]"):
			_, msg, _ := strings.Cut(line, "] ")
			t.log.Printf("tor: %s", msg)
		case strings.Contains(line, "Bootstrapped 100%"):
			t.log.Print("tor: connected to the tor network")
		}
	}
}

// Done is closed when tor exits.
func (t *Tor) Done() <-chan struct{} { return t.done }

// Err is why tor exited, once Done is closed.
func (t *Tor) Err() error {
	select {
	case <-t.done:
		if t.exitErr == nil {
			return errors.New("tor exited")
		}
		return fmt.Errorf("tor exited: %w", t.exitErr)
	default:
		return nil
	}
}

// Bootstrap is how far tor has got joining the network.
func (t *Tor) Bootstrap() (progress int, summary string, err error) {
	if err := t.Err(); err != nil {
		return 0, "", err
	}
	b, err := t.ctl.bootstrapPhase()
	if err != nil {
		return 0, "", err
	}
	return b.Progress, b.Summary, nil
}

// WaitReady blocks until tor has joined the network, or ctx ends.
func (t *Tor) WaitReady(ctx context.Context) error {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		p, summary, err := t.Bootstrap()
		if err != nil {
			return err
		}
		if p >= 100 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("tor is still connecting (%d%%: %s): %w", p, summary, ctx.Err())
		case <-t.done:
			return t.Err()
		case <-tick.C:
		}
	}
}

// Dial connects to address — an onion address, in practice — through tor.
func (t *Tor) Dial(ctx context.Context, address string) (net.Conn, error) {
	if err := t.Err(); err != nil {
		return nil, err
	}
	return socksDial(ctx, t.socks, address)
}

// Publish serves key's onion service, forwarding virtPort to target, for as
// long as this tor runs. It returns the onion address.
func (t *Tor) Publish(k Key, virtPort int, target string) (string, error) {
	if err := t.Err(); err != nil {
		return "", err
	}
	id, err := t.ctl.addOnion(k, virtPort, target)
	if err != nil {
		return "", fmt.Errorf("publish onion service: %w", err)
	}
	host := id + ".onion"
	if host != k.Host() {
		// Tor derived a different address from the key than makima did —
		// every node would be told one nobody answers at.
		_ = t.ctl.delOnion(id)
		return "", fmt.Errorf("tor published %s, but the key's address is %s", host, k.Host())
	}
	return host, nil
}

// Close stops tor. Closing the control connection is what stops it — tor was
// told it is owned by that connection — and it is killed if it lingers.
func (t *Tor) Close() {
	t.closeOnce.Do(func() {
		if t.ctl == nil {
			// Never attached, so never owned: nothing will tell it to stop.
			_ = t.cmd.Process.Kill()
		} else {
			_ = t.ctl.Close()
		}
		select {
		case <-t.done:
		case <-time.After(5 * time.Second):
			_ = t.cmd.Process.Kill()
			<-t.done
		}
	})
}
