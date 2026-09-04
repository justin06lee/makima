// Package supervise starts and stops makima's long-running processes.
//
// It exists so that `makima up` can be one command. Before it, bringing a node
// online meant knowing that a daemon existed, that it needed root, that it had
// to be launched separately from the CLI that configured it, and that the
// order mattered. None of that is interesting to somebody who wants their
// desktop to answer from the sofa.
//
// Liveness is decided by dialling the process's own Unix socket rather than by
// looking for a pid. A pid tells you a process exists; the socket tells you it
// exists, finished starting, and is answering — which is the thing every caller
// actually wants to know, and it stays true across a process the supervisor did
// not start itself, such as one launched by systemd.
package supervise

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Daemon is one process this package can bring up and take down.
type Daemon struct {
	// Name is the binary to run, looked up on PATH.
	Name string

	// Args are passed to it.
	Args []string

	// Socket is the Unix socket it listens on once it is ready. Dialling this
	// is how every other method decides whether it is running.
	Socket string

	// TCPAddr is the same idea for a process that has no Unix socket — the
	// relay listens on a TCP port and nothing else, so that port is the only
	// evidence it is up. Ignored when Socket is set.
	TCPAddr string

	// PIDFile is where the pid is recorded so Stop can find it again. Optional:
	// without it, Stop falls back to matching the process by name.
	PIDFile string

	// LogFile receives the process's output, since a detached daemon has no
	// terminal to write to and a silent failure is the worst kind.
	LogFile string
}

// Running reports whether the daemon is up and answering.
func (d Daemon) Running() bool {
	network, addr := "unix", d.Socket
	if addr == "" {
		network, addr = "tcp", d.TCPAddr
	}
	if addr == "" {
		return false
	}

	c, err := net.DialTimeout(network, addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Start launches the daemon and waits for it to answer.
//
// A no-op if it is already up, so `makima up` is safe to run twice — which
// people do constantly, because it is the command they remember.
func (d Daemon) Start(ctx context.Context, wait time.Duration) error {
	if d.Running() {
		return nil
	}

	bin, err := exec.LookPath(d.Name)
	if err != nil {
		return fmt.Errorf("cannot find %s on PATH — is makima installed? (try: make install)", d.Name)
	}

	logw, err := d.openLog()
	if err != nil {
		return err
	}
	defer logw.Close()

	cmd := exec.Command(bin, d.Args...)
	cmd.Stdout = logw
	cmd.Stderr = logw
	// Its own process group, so it survives the shell that started it and does
	// not take a Ctrl-C aimed at the CLI with it.
	cmd.SysProcAttr = detachAttrs()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", d.Name, err)
	}

	// Released rather than waited on: this is a daemon, and the CLI is about to
	// exit. Not reaping it is the point.
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	d.writePID(pid)

	if err := d.waitUntil(ctx, true, wait); err != nil {
		return fmt.Errorf("%s did not come up within %s — see %s", d.Name, wait, d.LogFile)
	}
	return nil
}

// Stop asks the daemon to exit and waits for it to let go of its socket.
//
// SIGTERM rather than SIGKILL, always: the daemon's shutdown path is what puts
// the routing table, the resolver and the firewall back the way it found them,
// and killing it outright would leave a machine that blackholes mesh addresses
// until the next reboot.
func (d Daemon) Stop(ctx context.Context, wait time.Duration) error {
	if !d.Running() {
		d.clearPID()
		return nil
	}

	pid, ok := d.readPID()
	if !ok {
		// Started by something else — systemd, a terminal, a previous install.
		// Find it by name rather than refusing to stop it.
		pid, ok = pidByName(d.Name)
	}
	if !ok {
		return fmt.Errorf("%s is running but its process could not be found; stop it by hand", d.Name)
	}

	if err := terminate(pid); err != nil {
		return fmt.Errorf("stop %s: %w", d.Name, err)
	}

	if err := d.waitUntil(ctx, false, wait); err != nil {
		return fmt.Errorf("%s did not stop within %s", d.Name, wait)
	}
	d.clearPID()
	return nil
}

// waitUntil polls the socket until it is in the wanted state.
func (d Daemon) waitUntil(ctx context.Context, up bool, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		if d.Running() == up {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("timed out")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (d Daemon) openLog() (*os.File, error) {
	if d.LogFile == "" {
		return os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}
	if err := os.MkdirAll(filepath.Dir(d.LogFile), 0o755); err != nil {
		return nil, fmt.Errorf("make log directory: %w", err)
	}
	f, err := os.OpenFile(d.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", d.LogFile, err)
	}
	return f, nil
}

func (d Daemon) writePID(pid int) {
	if d.PIDFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(d.PIDFile), 0o755); err != nil {
		return
	}
	// Best effort throughout: a missing pidfile costs Stop a process lookup,
	// which it can do anyway, so failing Start over it would be absurd.
	_ = os.WriteFile(d.PIDFile, []byte(strconv.Itoa(pid)), 0o644)
}

func (d Daemon) readPID() (int, bool) {
	if d.PIDFile == "" {
		return 0, false
	}
	b, err := os.ReadFile(d.PIDFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	// A pidfile outlives the process it named, and pids are reused. Confirm
	// something is there before signalling what might now be someone else.
	if !alive(pid) {
		return 0, false
	}
	return pid, true
}

func (d Daemon) clearPID() {
	if d.PIDFile != "" {
		_ = os.Remove(d.PIDFile)
	}
}

// pidByName finds a running process by executable name.
func pidByName(name string) (int, bool) {
	out, err := exec.Command("pgrep", "-x", name).Output()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Fields(string(out)) {
		if pid, err := strconv.Atoi(line); err == nil && pid > 0 && pid != os.Getpid() {
			return pid, true
		}
	}
	return 0, false
}
