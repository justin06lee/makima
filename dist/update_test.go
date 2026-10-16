package dist

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// update.sh runs against stand-ins for everything it asks the system: a fake
// launchctl, process table and clock, kept as files under one directory.
// They behave the way the real ones were seen to on macOS: launchctl bootout
// sends SIGTERM and returns at once, and the node is still on its way out —
// putting routes and the resolver back — for a while after.
const fakeLaunchctl = `#!/bin/sh
W=@W@
cmd=$1; shift
case $cmd in
print)
	l=${1#system/}
	[ -f "$W/jobs/$l" ] || { echo "Could not find service \"$l\" in domain for system"; exit 113; }
	printf 'system/%s = {\n\tactive count = 1\n\tpath = /Library/LaunchDaemons/%s.plist\n\targuments = {\n' "$l" "$l"
	for a in $(cat "$W/jobargs/$l"); do printf '\t\t%s\n' "$a"; done
	printf '\t}\n\n'
	pid=$(cat "$W/jobs/$l")
	[ -n "$pid" ] && printf '\tpid = %s\n' "$pid"
	printf '\tdefault environment = {\n\t\tPATH => /usr/bin:/bin\n\t}\n}\n'
	;;
bootout)
	l=${1#system/}
	echo "bootout $l" >> "$W/calls"
	[ -f "$W/jobs/$l" ] || exit 113
	pid=$(cat "$W/jobs/$l")
	rm -f "$W/jobs/$l"
	[ -n "$pid" ] && echo 3 > "$W/linger/$pid"
	exit 0
	;;
bootstrap)
	echo "bootstrap $(basename "$2" .plist)" >> "$W/calls"
	;;
esac
exit 0
`

// Time passes only when the script sleeps; a process that was told to stop
// is gone after three of them.
const fakeSleep = `#!/bin/sh
W=@W@
for f in "$W"/linger/*; do
	[ -f "$f" ] || continue
	n=$(($(cat "$f") - 1))
	if [ "$n" -le 0 ]; then rm -f "$f" "$W/procs/$(basename "$f")"; else echo "$n" > "$f"; fi
done
`

const fakePgrep = `#!/bin/sh
W=@W@
name=$2
found=1
for f in "$W"/procs/*; do
	[ -f "$f" ] || continue
	read -r prog rest < "$f"
	if [ "$(basename "$prog")" = "$name" ]; then basename "$f"; found=0; fi
done
exit $found
`

const fakePkill = `#!/bin/sh
W=@W@
name=$3
for f in "$W"/procs/*; do
	[ -f "$f" ] || continue
	read -r prog rest < "$f"
	[ "$(basename "$prog")" = "$name" ] && rm -f "$f" "$W/linger/$(basename "$f")"
done
exit 0
`

const fakePs = `#!/bin/sh
W=@W@
pid= args=
while [ $# -gt 0 ]; do
	case $1 in
	-p) pid=$2; shift ;;
	-o) args=1; shift ;;
	esac
	shift
done
[ -f "$W/procs/$pid" ] || exit 1
[ -n "$args" ] && cat "$W/procs/$pid"
exit 0
`

const fakeLog = `#!/bin/sh
echo "@NAME@ $*" >> @W@/calls
`

// nodeArgs is the command line launchd runs the node with.
const nodeArgs = "/Library/PrivilegedHelperTools/makima/makimad -config /etc/makima/node.json"

type fakeMac struct {
	t   *testing.T
	dir string // the fake system's state
	bin string // the fake commands
}

func newFakeMac(t *testing.T) *fakeMac {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("update.sh is a POSIX shell script")
	}
	if os.Geteuid() == 0 {
		// As root the script could reach the real /etc/sudoers.d and
		// /var/log/makima; nothing here should touch the machine running it.
		t.Skip("not run as root")
	}
	root := t.TempDir()
	m := &fakeMac{t: t, dir: filepath.Join(root, "sys"), bin: filepath.Join(root, "bin")}
	for _, d := range []string{m.bin, m.dir + "/jobs", m.dir + "/jobargs", m.dir + "/procs", m.dir + "/linger"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	scripts := map[string]string{
		"launchctl": fakeLaunchctl,
		"sleep":     fakeSleep,
		"pgrep":     fakePgrep,
		"pkill":     fakePkill,
		"ps":        fakePs,
		"id":        "#!/bin/sh\necho 0\n",
		"uname":     "#!/bin/sh\necho Darwin\n",
	}
	for _, name := range []string{"nohup", "open", "osascript", "sudo", "systemctl"} {
		scripts[name] = strings.ReplaceAll(fakeLog, "@NAME@", name)
	}
	for name, body := range scripts {
		body = strings.ReplaceAll(body, "@W@", m.dir)
		if err := os.WriteFile(filepath.Join(m.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	m.write("calls", "")
	return m
}

func (m *fakeMac) write(name, content string) {
	m.t.Helper()
	if err := os.WriteFile(filepath.Join(m.dir, name), []byte(content), 0o644); err != nil {
		m.t.Fatal(err)
	}
}

// job loads a launchd job running args, as pid — or, with pid empty, waiting
// for launchd to start it again.
func (m *fakeMac) job(label, args, pid string) {
	m.write("jobs/"+label, pid)
	m.write("jobargs/"+label, args)
	if pid != "" {
		m.proc(pid, args)
	}
}

func (m *fakeMac) proc(pid, args string) { m.write("procs/"+pid, args) }

func (m *fakeMac) run(verb string) string {
	m.t.Helper()
	cmd := exec.Command("sh", "update.sh", verb)
	cmd.Env = []string{
		"PATH=" + m.bin + ":/usr/bin:/bin",
		"TMPDIR=" + filepath.Dir(m.dir),
		"MAKIMA_UPDATE_STATE=" + filepath.Join(filepath.Dir(m.dir), "state"),
	}
	// What it starts with nohup it leaves running in the background. Each
	// inherits the write end of this pipe, so reading it to the end waits
	// for them as well as for the script.
	r, w, err := os.Pipe()
	if err != nil {
		m.t.Fatal(err)
	}
	defer r.Close()
	cmd.ExtraFiles = []*os.File{w}
	out, err := cmd.CombinedOutput()
	w.Close()
	_, _ = io.Copy(io.Discard, r)
	if err != nil {
		m.t.Fatalf("update.sh %s: %v\n%s", verb, err, out)
	}
	return string(out)
}

func (m *fakeMac) calls() []string {
	m.t.Helper()
	b, err := os.ReadFile(filepath.Join(m.dir, "calls"))
	if err != nil {
		m.t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (m *fakeMac) running() []string {
	m.t.Helper()
	ents, err := os.ReadDir(filepath.Join(m.dir, "procs"))
	if err != nil {
		m.t.Fatal(err)
	}
	var pids []string
	for _, e := range ents {
		pids = append(pids, e.Name())
	}
	return pids
}

func started(calls []string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, "bootstrap ") || strings.HasPrefix(c, "nohup ") {
			out = append(out, c)
		}
	}
	return out
}

// A node launchd runs is started again by launchd alone. bootout returning
// before the node has exited made it look started by hand, so it came back
// twice — under launchd and under nohup — one copy losing UDP 51820, and when
// that was launchd's, KeepAlive retried it every ten seconds for as long as
// the other ran: thousands of "bind: address already in use" on the Mac.
func TestUpdateRestartsALaunchdNodeOnce(t *testing.T) {
	m := newFakeMac(t)
	m.job("sh.makima.makimad", nodeArgs, "100")

	m.run("stop")
	if pids := m.running(); len(pids) != 0 {
		t.Fatalf("still running after stop: %v", pids)
	}
	m.run("start")

	want := []string{"bootstrap sh.makima.makimad"}
	if got := started(m.calls()); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("started %q, want %q", got, want)
	}
}

// The state that left behind: launchd's job waiting to retry, and a copy of
// it running outside launchd. The next update puts it back under launchd —
// one copy, which launchd watches — rather than repeating it.
func TestUpdateFoldsAStrayCopyBackIntoLaunchd(t *testing.T) {
	m := newFakeMac(t)
	m.job("sh.makima.makimad", nodeArgs, "")
	m.proc("200", nodeArgs)

	m.run("stop")
	if pids := m.running(); len(pids) != 0 {
		t.Fatalf("still running after stop: %v", pids)
	}
	m.run("start")

	want := []string{"bootstrap sh.makima.makimad"}
	if got := started(m.calls()); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("started %q, want %q", got, want)
	}
}

// A node somebody started by hand is still started the same way again.
func TestUpdateRestartsAHandStartedNodeByHand(t *testing.T) {
	m := newFakeMac(t)
	m.proc("300", "/usr/local/bin/makimad -config /tmp/node.json")

	m.run("stop")
	m.run("start")

	want := []string{"nohup /usr/local/bin/makimad -config /tmp/node.json"}
	if got := started(m.calls()); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("started %q, want %q", got, want)
	}
}
