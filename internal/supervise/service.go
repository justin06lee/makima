package supervise

import (
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Service is how a Daemon is registered with the machine's service manager —
// launchd on macOS, systemd on Linux — so that it comes back after a reboot
// and is restarted if it dies.
//
// This is what makes `makima up` mean "up" rather than "up until the next
// restart". Every other mesh VPN app works this way, and somebody who clicked
// Connect once and rebooted expects to still be connected; the alternative is
// a machine that silently drops off the network every time it restarts, and a
// person who has to learn what a daemon is to find out why.
//
// A Daemon with no Service is started directly, as before, which is what
// happens on platforms without a manager and when the manager refuses.
type Service struct {
	// Label is the launchd label, e.g. "sh.makima.makimad". It names the
	// plist in /Library/LaunchDaemons.
	Label string

	// Unit is the systemd unit name without ".service", e.g. "makimad".
	Unit string

	// Description is one line for the unit file.
	Description string
}

// manager is one platform's service manager, as much of it as the supervisor
// needs. An interface so the decision logic in Start and Stop can be tested
// against a fake, since the real ones need root and a running init system.
type manager interface {
	// name is what to call it in a message: "launchd", "systemd".
	name() string

	// registered reports whether the daemon's definition is installed —
	// whether the machine will start it at boot.
	registered(d Daemon) bool

	// register installs the definition and starts the daemon under it,
	// replacing any earlier definition. bin is the binary to run, already
	// located.
	register(d Daemon, bin string) error

	// unregister stops the daemon and removes the definition, so it stays
	// down across reboots until registered again. A definition that is not
	// there is not an error.
	unregister(d Daemon) error
}

// findManager is how Start and Stop get the manager for this machine, if any.
// A variable so tests can hand them a fake.
var findManager = platformManager

// available reports whether a manager exists here and this daemon can use it:
// it names a service, the process is root, and the platform's manager is
// actually present rather than merely being the platform's convention.
func available(d Daemon) (manager, bool) {
	return findManager(d)
}

// isRoot is the one precondition every real manager shares: their definitions
// live in directories only root can write, and their control commands refuse
// anybody else.
func isRoot() bool { return os.Geteuid() == 0 }

// logFor is where to tell somebody to look when a daemon did not come up.
func (d Daemon) logFor() string {
	if d.LogFile != "" {
		return d.LogFile
	}
	return "its output"
}

// envList renders Env as KEY=VALUE pairs, sorted so the output is stable.
func (d Daemon) envList() []string {
	out := make([]string, 0, len(d.Env))
	for k, v := range d.Env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// launchdPlist renders a LaunchDaemon definition.
//
// RunAtLoad and KeepAlive together are the whole point: the tunnel exists
// before anybody logs in, and comes back if it dies. ExitTimeOut is generous
// because SIGTERM is what puts the routing table and the resolver back, and
// twenty seconds of patience is cheaper than a machine that blackholes mesh
// addresses until it reboots.
func launchdPlist(d Daemon, bin string) string {
	var b strings.Builder
	esc := func(s string) string {
		var sb strings.Builder
		_ = xml.EscapeText(&sb, []byte(s))
		return sb.String()
	}

	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	fmt.Fprintf(&b, "  <key>Label</key>\n  <string>%s</string>\n", esc(d.Service.Label))

	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	fmt.Fprintf(&b, "    <string>%s</string>\n", esc(bin))
	for _, a := range d.Args {
		fmt.Fprintf(&b, "    <string>%s</string>\n", esc(a))
	}
	b.WriteString("  </array>\n")

	if len(d.Env) > 0 {
		b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
		for _, kv := range d.envList() {
			k, v, _ := strings.Cut(kv, "=")
			fmt.Fprintf(&b, "    <key>%s</key>\n    <string>%s</string>\n", esc(k), esc(v))
		}
		b.WriteString("  </dict>\n")
	}

	b.WriteString("  <key>RunAtLoad</key>\n  <true/>\n")
	b.WriteString("  <key>KeepAlive</key>\n  <true/>\n")
	b.WriteString("  <key>ExitTimeOut</key>\n  <integer>20</integer>\n")

	if d.LogFile != "" {
		fmt.Fprintf(&b, "  <key>StandardOutPath</key>\n  <string>%s</string>\n", esc(d.LogFile))
		fmt.Fprintf(&b, "  <key>StandardErrorPath</key>\n  <string>%s</string>\n", esc(d.LogFile))
	}

	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

// unitMarker opens every unit makima writes, so it can tell its own from one
// somebody installed in the same place — from dist/, or by a package — which
// it starts and stops but never rewrites or removes (see ownUnit).
const unitMarker = "# Written by makima. A unit installed by hand in its place is left alone.\n"

// ownUnit reports whether makima wrote a unit: it carries the marker, or —
// written before there was one — it has no Documentation line, which every
// unit in dist/ has and no unit makima writes ever did.
func ownUnit(b []byte) bool {
	return strings.HasPrefix(string(b), unitMarker) || !strings.Contains(string(b), "\nDocumentation=")
}

// systemdUnit renders a unit file.
//
// Plain root, deliberately, and the same is true of the node daemon's unit in
// dist/: the daemon binds port 53 for mesh names, changes to the owner's
// account for a shell session, hands the inbox and the desktop socket to its
// owner, reads authorized_keys in their home, drives the distribution's
// firewall tools, and replaces its own binaries when the network moves to a
// new release. Every narrowing tried so far broke one of those without saying
// so. The control plane and the relay need none of it, and their units in
// dist/ are confined.
func systemdUnit(d Daemon, bin string) string {
	var b strings.Builder

	b.WriteString(unitMarker)
	b.WriteString("[Unit]\n")
	fmt.Fprintf(&b, "Description=%s\n", d.Service.Description)
	b.WriteString("After=network-online.target\nWants=network-online.target\n\n")

	b.WriteString("[Service]\nType=simple\n")
	fmt.Fprintf(&b, "ExecStart=%s", systemdQuote(bin))
	for _, a := range d.Args {
		b.WriteString(" " + systemdQuote(a))
	}
	b.WriteString("\n")
	for _, kv := range d.envList() {
		fmt.Fprintf(&b, "Environment=%s\n", systemdQuote(kv))
	}
	b.WriteString("Restart=always\nRestartSec=3\n")
	b.WriteString("KillSignal=SIGTERM\nTimeoutStopSec=20\n")
	if d.LogFile != "" {
		fmt.Fprintf(&b, "StandardOutput=append:%s\nStandardError=append:%s\n", d.LogFile, d.LogFile)
	}

	b.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

// systemdQuote quotes one word for an ExecStart or Environment line. Double
// quotes with backslash escapes are what systemd's unit parser accepts.
func systemdQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$;") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
