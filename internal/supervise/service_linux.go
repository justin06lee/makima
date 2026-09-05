package supervise

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// systemd is Linux's service manager, on the distributions that have it —
// which is nearly all of them. A machine without it, or a container, gets the
// daemon started directly instead, exactly as before.
type systemd struct{}

const systemdUnits = "/etc/systemd/system"

func platformManager(d Daemon) (manager, bool) {
	if d.Service.Unit == "" || !isRoot() {
		return nil, false
	}
	// The directory exists only when systemd is the running init, which is
	// the question that matters: a systemctl binary on a machine booted by
	// something else can do nothing useful.
	if fi, err := os.Stat("/run/systemd/system"); err != nil || !fi.IsDir() {
		return nil, false
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, false
	}
	return systemd{}, true
}

func (systemd) name() string { return "systemd" }

func unitPath(d Daemon) string {
	return filepath.Join(systemdUnits, d.Service.Unit+".service")
}

func (systemd) registered(d Daemon) bool {
	_, err := os.Stat(unitPath(d))
	return err == nil
}

func (systemd) register(d Daemon, bin string) error {
	path := unitPath(d)
	if err := os.MkdirAll(systemdUnits, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(systemdUnit(d, bin)), 0o644); err != nil {
		return err
	}

	if out, err := systemctl("daemon-reload"); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("systemctl daemon-reload: %s", out)
	}
	if out, err := systemctl("enable", d.Service.Unit); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("systemctl enable: %s", out)
	}
	// restart rather than start: a unit that was already active under an old
	// definition picks up the new one, and one that was not is simply started.
	if out, err := systemctl("restart", d.Service.Unit); err != nil {
		_, _ = systemctl("disable", d.Service.Unit)
		_ = os.Remove(path)
		return fmt.Errorf("systemctl restart: %s", out)
	}
	return nil
}

func (systemd) unregister(d Daemon) error {
	// A unit that is not loaded makes this complain; that is the state being
	// asked for, so the complaint is not interesting.
	_, _ = systemctl("disable", "--now", d.Service.Unit)
	if err := os.Remove(unitPath(d)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, _ = systemctl("daemon-reload")
	return nil
}

func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if err != nil && last == "" {
		last = err.Error()
	}
	return last, err
}
