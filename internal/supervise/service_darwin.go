package supervise

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// launchd is macOS's service manager.
//
// A LaunchDaemon rather than a LaunchAgent: creating a utun device and editing
// the routing table needs root, and the tunnel should exist before anyone logs
// in. The definition lives in /Library/LaunchDaemons, which is where launchd
// looks for exactly this kind of thing at boot.
type launchd struct{}

const launchDaemons = "/Library/LaunchDaemons"

func platformManager(d Daemon) (manager, bool) {
	if d.Service.Label == "" || !isRoot() {
		return nil, false
	}
	if _, err := exec.LookPath("launchctl"); err != nil {
		return nil, false
	}
	return launchd{}, true
}

func (launchd) name() string { return "launchd" }

func plistPath(d Daemon) string {
	return filepath.Join(launchDaemons, d.Service.Label+".plist")
}

func (launchd) registered(d Daemon) bool {
	_, err := os.Stat(plistPath(d))
	return err == nil
}

func (l launchd) register(d Daemon, bin string) error {
	path := plistPath(d)
	target := "system/" + d.Service.Label

	if err := os.MkdirAll(launchDaemons, 0o755); err != nil {
		return err
	}
	// launchd refuses a definition that anybody but root could edit, so the
	// mode matters as much as the content.
	if err := os.WriteFile(path, []byte(launchdPlist(d, bin)), 0o644); err != nil {
		return err
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return fmt.Errorf("own %s: %w", path, err)
	}

	// Whatever was loaded under this label before is taken out first, so a
	// definition that changed — a binary that moved into an app bundle, say —
	// is what runs rather than what used to. Nothing loaded is not an error.
	_, _ = launchctl("bootout", target)
	// Undo an earlier `launchctl disable`, which would otherwise make the
	// bootstrap below fail with a message about the service being disabled.
	_, _ = launchctl("enable", target)

	if out, err := launchctl("bootstrap", "system", path); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("launchctl bootstrap: %s", out)
	}
	return nil
}

func (launchd) unregister(d Daemon) error {
	path := plistPath(d)
	// bootout sends SIGTERM and waits for the process, up to ExitTimeOut. Its
	// error for "nothing loaded" is ignored: the definition may be on disk
	// from a previous boot with nothing running under it, and either way the
	// outcome wanted is the same.
	_, _ = launchctl("bootout", "system/"+d.Service.Label)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// launchctl runs one launchctl command and returns the last line it said,
// which is the one that explains a failure.
func launchctl(args ...string) (string, error) {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if err != nil && last == "" {
		last = err.Error()
	}
	return last, err
}
