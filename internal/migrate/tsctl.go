package migrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Host is how this file touches the machine it runs on, so that tests can
// watch what it would do instead of doing it.
type Host struct {
	GOOS   string
	Run    func(ctx context.Context, name string, args ...string) (string, error)
	Exists func(path string) bool
}

// ThisHost is the real machine.
func ThisHost() Host {
	return Host{
		GOOS: runtime.GOOS,
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH")+":/usr/local/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/run/current-system/sw/bin")
			cmd.WaitDelay = 2 * time.Second
			out, err := cmd.CombinedOutput()
			s := strings.TrimSpace(string(out))
			if err != nil && s != "" {
				return s, fmt.Errorf("%s: %s", name, lastLine(s))
			}
			return s, err
		},
		Exists: func(p string) bool { _, err := os.Stat(p); return err == nil },
	}
}

func (h Host) has(name string) bool {
	_, err := h.Run(context.Background(), "sh", "-c", "command -v "+ShellQuote(name))
	return err == nil
}

// Tailscale is the Tailscale on this machine, and how to stop, restart and
// remove it. Run as root.
type Tailscale struct {
	h   Host
	CLI string

	// Kind is who keeps tailscaled running: "systemd", "openrc", "app" (the
	// macOS app, whose engine is a network extension), "daemon" (tailscaled
	// installed as a macOS system daemon), or "cli" (nothing we can stop
	// but the connection itself).
	Kind string

	// Pkg is how it was installed, which is how it is removed.
	Pkg string

	// console is the person logged in at the Mac. The app's CLI talks to the
	// app running in their session, so it is run as them.
	console string

	wasActive bool
}

const macApp = "/Applications/Tailscale.app"

// FindTailscale looks for Tailscale on this machine.
func FindTailscale(ctx context.Context, h Host) (*Tailscale, bool) {
	t := &Tailscale{h: h}
	for _, p := range []string{
		macApp + "/Contents/MacOS/Tailscale",
		"/usr/bin/tailscale", "/usr/local/bin/tailscale", "/usr/sbin/tailscale",
		"/opt/homebrew/bin/tailscale", "/run/current-system/sw/bin/tailscale",
	} {
		if h.Exists(p) {
			t.CLI = p
			break
		}
	}

	switch h.GOOS {
	case "darwin":
		if h.Exists(macApp) {
			t.Kind, t.Pkg = "app", "app"
			if u, err := h.Run(ctx, "stat", "-f", "%Su", "/dev/console"); err == nil && u != "" && u != "root" {
				t.console = u
			}
		} else if t.CLI != "" {
			t.Kind, t.Pkg = "daemon", "daemon"
		}
	default:
		switch {
		case h.Exists("/run/systemd/system") && t.unitExists(ctx):
			t.Kind = "systemd"
		case h.Exists("/etc/init.d/tailscale") && h.has("rc-service"):
			t.Kind = "openrc"
		case t.CLI != "":
			t.Kind = "cli"
		}
		t.Pkg = t.linuxPkg(ctx)
	}
	if t.Kind == "" {
		return nil, false
	}
	return t, true
}

func (t *Tailscale) unitExists(ctx context.Context) bool {
	_, err := t.h.Run(ctx, "systemctl", "cat", "tailscaled.service")
	return err == nil
}

func (t *Tailscale) linuxPkg(ctx context.Context) string {
	try := func(name string, args ...string) bool {
		if !t.h.has(name) {
			return false
		}
		_, err := t.h.Run(ctx, name, args...)
		return err == nil
	}
	switch {
	case t.h.Exists("/etc/NIXOS"):
		return "nix"
	case try("pacman", "-Qq", "tailscale"):
		return "pacman"
	case try("dpkg-query", "-W", "tailscale"):
		return "apt"
	case try("rpm", "-q", "tailscale"):
		return "rpm"
	case try("apk", "info", "-e", "tailscale"):
		return "apk"
	case try("snap", "list", "tailscale"):
		return "snap"
	}
	return "manual"
}

// cli runs the tailscale command — as the person at the console, for the
// macOS app.
func (t *Tailscale) cli(ctx context.Context, args ...string) (string, error) {
	if t.CLI == "" {
		return "", ErrNoTailscale
	}
	if t.Kind == "app" && t.console != "" {
		return t.h.Run(ctx, "sudo", append([]string{"-u", t.console, t.CLI}, args...)...)
	}
	return t.h.Run(ctx, t.CLI, args...)
}

// Active says whether Tailscale is up right now.
func (t *Tailscale) Active(ctx context.Context) bool {
	switch t.Kind {
	case "systemd":
		out, _ := t.h.Run(ctx, "systemctl", "is-active", "tailscaled")
		return strings.TrimSpace(out) == "active"
	case "openrc":
		_, err := t.h.Run(ctx, "rc-service", "tailscale", "status")
		return err == nil
	}
	out, err := t.cli(ctx, "status", "--json")
	if err != nil {
		return false
	}
	st, err := ParseStatus([]byte(out))
	return err == nil && st.Running()
}

// Stop takes Tailscale off the network without forgetting anything, so Start
// puts it back exactly.
//
// On Linux the daemon itself is stopped, not merely disconnected: while it
// runs it drops every packet from 100.64.0.0/10 that did not arrive on its own
// interface, and makima's addresses are in that range. Stopping it removes
// that rule; --cleanup makes sure.
func (t *Tailscale) Stop(ctx context.Context) error {
	t.wasActive = t.Active(ctx)
	var err error
	switch t.Kind {
	case "systemd":
		_, err = t.h.Run(ctx, "systemctl", "stop", "tailscaled")
	case "openrc":
		_, err = t.h.Run(ctx, "rc-service", "tailscale", "stop")
	default:
		_, err = t.cli(ctx, "down")
	}
	if err != nil {
		return fmt.Errorf("stop tailscale: %w", err)
	}
	t.cleanup(ctx)
	return nil
}

// Start undoes Stop.
func (t *Tailscale) Start(ctx context.Context) error {
	if !t.wasActive {
		return nil
	}
	var err error
	switch t.Kind {
	case "systemd":
		_, err = t.h.Run(ctx, "systemctl", "start", "tailscaled")
	case "openrc":
		_, err = t.h.Run(ctx, "rc-service", "tailscale", "start")
	default:
		_, err = t.cli(ctx, "up")
	}
	if err != nil {
		return fmt.Errorf("start tailscale again: %w", err)
	}
	return nil
}

// Disable keeps a stopped Tailscale from coming back at the next boot, for a
// machine that switched but was asked to keep Tailscale installed.
func (t *Tailscale) Disable(ctx context.Context) {
	switch t.Kind {
	case "systemd":
		_, _ = t.h.Run(ctx, "systemctl", "disable", "tailscaled")
	case "openrc":
		_, _ = t.h.Run(ctx, "rc-update", "del", "tailscale")
	}
}

// cleanup removes whatever tailscaled left in the firewall and routing tables.
func (t *Tailscale) cleanup(ctx context.Context) {
	if t.h.GOOS != "linux" {
		return
	}
	for _, p := range []string{"/usr/sbin/tailscaled", "/usr/bin/tailscaled", "/usr/local/bin/tailscaled", "/run/current-system/sw/bin/tailscaled"} {
		if t.h.Exists(p) {
			_, _ = t.h.Run(ctx, p, "--cleanup")
			return
		}
	}
}

// Remove signs the machine out of the tailnet and uninstalls Tailscale.
//
// Each step is attempted whatever happened to the one before, and what could
// not be done comes back as a note: by the time this runs the machine is on
// makima, so a leftover is untidy rather than dangerous, and one failed step
// is no reason to leave the rest undone.
func (t *Tailscale) Remove(ctx context.Context) (notes []string, err error) {
	note := func(format string, a ...any) { notes = append(notes, fmt.Sprintf(format, a...)) }
	step := func(d time.Duration, name string, args ...string) error {
		c, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		_, e := t.h.Run(c, name, args...)
		return e
	}

	if t.h.GOOS == "darwin" {
		return t.removeMac(ctx)
	}

	// Signing out needs the daemon, which Stop took down. It comes back for
	// a few seconds — long enough to tell the tailnet this machine is gone,
	// so it does not linger in the admin console as an offline device.
	if t.Kind == "systemd" {
		_ = step(20*time.Second, "systemctl", "start", "tailscaled")
	} else if t.Kind == "openrc" {
		_ = step(20*time.Second, "rc-service", "tailscale", "start")
	}
	lc, cancel := context.WithTimeout(ctx, 20*time.Second)
	if _, e := t.cli(lc, "logout"); e != nil {
		note("could not sign out of Tailscale (%v) — remove this machine from the Tailscale admin console", e)
	}
	cancel()

	switch t.Kind {
	case "systemd":
		_ = step(30*time.Second, "systemctl", "disable", "--now", "tailscaled")
	case "openrc":
		_ = step(30*time.Second, "rc-service", "tailscale", "stop")
		_ = step(10*time.Second, "rc-update", "del", "tailscale")
	}
	t.cleanup(ctx)

	var rm error
	switch t.Pkg {
	case "pacman":
		rm = step(2*time.Minute, "pacman", "-Rns", "--noconfirm", "tailscale")
	case "apt":
		rm = step(3*time.Minute, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "purge", "-y", "tailscale")
	case "rpm":
		switch {
		case t.h.has("dnf"):
			rm = step(3*time.Minute, "dnf", "remove", "-y", "tailscale")
		case t.h.has("zypper"):
			rm = step(3*time.Minute, "zypper", "-n", "rm", "tailscale")
		default:
			rm = step(3*time.Minute, "yum", "remove", "-y", "tailscale")
		}
	case "apk":
		rm = step(2*time.Minute, "apk", "del", "tailscale")
	case "snap":
		rm = step(2*time.Minute, "snap", "remove", "tailscale")
	case "nix":
		note("Tailscale is declared in this machine's NixOS configuration; it is stopped and disabled, and stays gone once services.tailscale is removed there")
		return notes, nil
	default:
		for _, p := range []string{
			"/usr/bin/tailscale", "/usr/sbin/tailscaled", "/usr/bin/tailscaled",
			"/usr/local/bin/tailscale", "/usr/local/bin/tailscaled",
			"/etc/systemd/system/tailscaled.service", "/lib/systemd/system/tailscaled.service",
		} {
			if t.h.Exists(p) {
				_ = step(10*time.Second, "rm", "-f", p)
			}
		}
		if t.Kind == "systemd" {
			_ = step(20*time.Second, "systemctl", "daemon-reload")
		}
	}
	if rm != nil {
		note("the tailscale package would not uninstall (%v); it is stopped and disabled, and can be removed by hand", rm)
		return notes, nil
	}
	// Its state holds the machine's Tailscale identity, which is no use to
	// anyone once the machine has left.
	_ = step(10*time.Second, "rm", "-rf", "/var/lib/tailscale")
	return notes, nil
}

func (t *Tailscale) removeMac(ctx context.Context) (notes []string, err error) {
	note := func(format string, a ...any) { notes = append(notes, fmt.Sprintf(format, a...)) }
	try := func(d time.Duration, args ...string) error {
		c, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		_, e := t.cli(c, args...)
		return e
	}

	if e := try(20*time.Second, "logout"); e != nil {
		note("could not sign out of Tailscale (%v) — remove this Mac from the Tailscale admin console", e)
	}

	if t.Kind == "daemon" {
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		for _, p := range []string{"/usr/local/bin/tailscaled", "/opt/homebrew/bin/tailscaled"} {
			if t.h.Exists(p) {
				if _, e := t.h.Run(c, p, "uninstall-system-daemon"); e != nil {
					note("tailscaled would not uninstall itself: %v", e)
				}
			}
		}
		for _, brew := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
			if !t.h.Exists(brew) {
				continue
			}
			// Homebrew refuses to run as root; it is run as whoever owns it.
			if owner, e := t.h.Run(c, "stat", "-f", "%Su", brew); e == nil && owner != "" && owner != "root" {
				_, _ = t.h.Run(c, "sudo", "-u", owner, brew, "uninstall", "tailscale")
			}
		}
		return notes, nil
	}

	// The app: its VPN entry in System Settings, its system extension, the
	// app itself, and the shim the app puts in /usr/local/bin.
	_ = try(20*time.Second, "configure", "mac-vpn", "uninstall")
	if e := try(45*time.Second, "configure", "sysext", "deactivate"); e != nil {
		note("the Tailscale system extension is still registered until the next restart")
	}
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if t.console != "" {
		_, _ = t.h.Run(c, "sudo", "-u", t.console, "osascript", "-e", `quit app "Tailscale"`)
	}
	_, _ = t.h.Run(c, "pkill", "-x", "Tailscale")
	if _, e := t.h.Run(c, "rm", "-rf", macApp); e != nil {
		note("could not delete %s: %v", macApp, e)
	}
	if shim, e := t.h.Run(c, "cat", "/usr/local/bin/tailscale"); e == nil && strings.Contains(shim, "Tailscale.app") {
		_, _ = t.h.Run(c, "rm", "-f", "/usr/local/bin/tailscale")
	}
	return notes, nil
}

// ErrNotRoot is what the on-machine half says when it is run without root.
var ErrNotRoot = errors.New("this part of the migration runs as root")
