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
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Daemon is one process this package can bring up and take down.
type Daemon struct {
	// Name is the binary to run, found by Locate: beside this program first,
	// then on PATH.
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

	// Service is how this daemon is registered with launchd or systemd, so it
	// survives a reboot. Leave it empty for a process that should only last
	// as long as the session.
	Service Service

	// Env is handed to the process on top of the environment it inherits —
	// and written into its service definition, which is how a daemon started
	// at boot still knows who it is running for.
	Env map[string]string
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
//
// Where the machine has a service manager and the daemon names a service, it
// is registered there and started by it, so that it is back after a reboot
// without anybody remembering to bring it back. Where that is not possible —
// no manager, not root, or the manager refuses — it is started directly, and
// lasts until the machine restarts.
func (d Daemon) Start(ctx context.Context, wait time.Duration) error {
	if d.Running() {
		return nil
	}

	bin, err := Locate(d.Name)
	if err != nil {
		return err
	}

	if m, ok := available(d); ok {
		if err := m.register(d, bin); err == nil {
			if err := d.waitUntil(ctx, true, wait); err == nil {
				return nil
			}
			// Registered, but never answered. Left in place, the manager
			// would keep restarting something that does not work, and the
			// next `makima up` would find a service that looks installed and
			// a daemon that is not there.
			_ = m.unregister(d)
			return fmt.Errorf("%s did not come up within %s — see %s", d.Name, wait, d.logFor())
		} else {
			fmt.Fprintf(os.Stderr, "note: %s will not come back after a reboot: %s could not register it (%v)\n", d.Name, m.name(), err)
		}
	}

	return d.spawn(ctx, bin, wait)
}

// spawn starts the daemon as a detached child of this process.
func (d Daemon) spawn(ctx context.Context, bin string, wait time.Duration) error {
	logw, err := d.openLog()
	if err != nil {
		return err
	}
	defer logw.Close()

	cmd := exec.Command(bin, d.Args...)
	cmd.Stdout = logw
	cmd.Stderr = logw
	cmd.Env = append(os.Environ(), d.envList()...)
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
		return fmt.Errorf("%s did not come up within %s — see %s", d.Name, wait, d.logFor())
	}
	return nil
}

// Stop asks the daemon to exit and waits for it to let go of its socket.
//
// SIGTERM rather than SIGKILL, always: the daemon's shutdown path is what puts
// the routing table, the resolver and the firewall back the way it found them,
// and killing it outright would leave a machine that blackholes mesh addresses
// until the next reboot.
//
// A daemon registered with the service manager is taken out of it as well —
// otherwise the manager would start it again immediately, and again at the
// next boot, and "down" would mean nothing.
func (d Daemon) Stop(ctx context.Context, wait time.Duration) error {
	if m, ok := available(d); ok && m.registered(d) {
		if err := m.unregister(d); err != nil {
			return fmt.Errorf("stop %s: %w", d.Name, err)
		}
		if err := d.waitUntil(ctx, false, wait); err == nil {
			d.clearPID()
			return nil
		}
		// Still answering: the running process was not the manager's after
		// all — started by hand, or by an older makima — so it is stopped
		// the direct way below.
	}

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

// Locate finds one of makima's binaries.
//
// Beside the running executable first, then on PATH, then in the places
// things get installed. The order matters for two reasons. The desktop app
// carries all four binaries inside its bundle and runs the CLI from there, so
// "the makimad next to this makima" is the one built and shipped with it. And
// the shell behind a graphical admin prompt — osascript on macOS, pkexec on
// Linux — has a PATH so short that /usr/local/bin is not on it, which used to
// make the app's Connect button fail with advice about running make.
func Locate(name string) (string, error) {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}

	if self, err := os.Executable(); err == nil {
		// A symlink in /usr/local/bin pointing into an app bundle should find
		// the daemons in the bundle, not in /usr/local/bin.
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
		if p := filepath.Join(filepath.Dir(self), name); runnable(p) {
			return p, nil
		}
	}

	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}

	for _, dir := range []string{"/usr/local/bin", "/opt/homebrew/bin", "/usr/bin"} {
		if p := filepath.Join(dir, name); runnable(p) {
			return p, nil
		}
	}

	return "", fmt.Errorf("%s is missing, so makima is not fully installed here — reinstall the app, or run the install script from https://github.com/justin06lee/makima", name)
}

// runnable reports whether a path is a file somebody could execute.
func runnable(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return false
	}
	return runtime.GOOS == "windows" || fi.Mode()&0o111 != 0
}
