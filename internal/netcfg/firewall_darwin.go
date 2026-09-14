//go:build darwin

package netcfg

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// macOS's firewall judges by application, not by port or interface: an app
// may accept incoming connections or it may not, on every interface at once —
// the tunnel included. So trusting the tunnel here means the one thing this
// firewall can be told: that makimad may accept connections.
//
// Signed software is often let through on its own. A build without Apple's
// signature is not, and a daemon has nobody at the screen to click Allow, so
// its connections are dropped without a word — files sent to this Mac, its
// published ports, the built-in SSH server and mesh names all stop answering
// the other devices, while everything this Mac starts itself keeps working.
//
// "Block all incoming connections" overrides every per-app rule. That one is
// the person's to turn off; makima only says so.

const socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

func firewallStatus(iface string) Report {
	if !alf("--getglobalstate", "enabled") {
		return Report{
			Backend: BackendNone,
			Trusted: true,
			Detail:  "the macOS firewall is off, so nothing filters tunnel traffic",
		}
	}

	r := Report{Backend: BackendALF, Active: true, Automatic: true}
	if alf("--getblockall", "set to enabled") {
		r.Automatic = false
		r.Manual = "System Settings → Network → Firewall → Options, and turn off “Block all incoming connections”"
		r.Detail = "the macOS firewall is blocking all incoming connections, so other devices cannot reach anything makima offers here"
		return r
	}

	exe, err := daemonPath()
	if err != nil {
		r.Automatic = false
		r.Detail = fmt.Sprintf("the macOS firewall is on, and makimad could not find itself to check it: %v", err)
		return r
	}
	r.Manual = fmt.Sprintf("sudo %s --add %s && sudo %s --unblockapp %s", socketfilterfw, exe, socketfilterfw, exe)
	r.Trusted = alf("--getappblocked "+exe, "is permitted")
	if r.Trusted {
		r.Detail = "the macOS firewall is on, and lets makima accept connections"
	} else {
		r.Detail = "the macOS firewall is on and blocks makima's incoming connections, so other devices cannot reach what it offers here"
	}
	return r
}

func firewallAllow(iface string, b Backend) error {
	if b != BackendALF {
		return nil
	}
	exe, err := daemonPath()
	if err != nil {
		return err
	}
	for _, flag := range []string{"--add", "--unblockapp"} {
		if out, err := exec.Command(socketfilterfw, flag, exe).CombinedOutput(); err != nil {
			return fmt.Errorf("socketfilterfw %s: %v: %s", flag, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// firewallReset takes makimad back out of the list. Left in, every app update
// — a new path, or a new build at the old one — would leave another entry
// behind for somebody to wonder about.
func firewallReset(iface string, b Backend) error {
	if b != BackendALF {
		return nil
	}
	exe, err := daemonPath()
	if err != nil {
		return err
	}
	return exec.Command(socketfilterfw, "--remove", exe).Run()
}

// OpenPort has nothing to do: the firewall asks about makimad, not its ports.
func OpenPort(proto string, port int) (string, error) { return "", nil }

// alf runs socketfilterfw and says whether its answer contains want.
func alf(args, want string) bool {
	out, err := exec.Command(socketfilterfw, strings.Fields(args)...).Output()
	return err == nil && strings.Contains(string(out), want)
}

// daemonPath is this process's executable, as the firewall lists it.
func daemonPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}
