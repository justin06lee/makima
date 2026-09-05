package supervise

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeManager stands in for launchd or systemd: it records what was asked and
// can be told to refuse, and it "starts" the daemon by listening on its
// socket itself, which is all Running() looks at.
type fakeManager struct {
	registerErr error
	registered_ bool
	registers   int
	unregisters int
	ln          net.Listener
}

func (f *fakeManager) name() string           { return "fake" }
func (f *fakeManager) registered(Daemon) bool { return f.registered_ }
func (f *fakeManager) register(d Daemon, _ string) error {
	f.registers++
	if f.registerErr != nil {
		return f.registerErr
	}
	ln, err := net.Listen("unix", d.Socket)
	if err != nil {
		return err
	}
	f.ln = ln
	f.registered_ = true
	return nil
}
func (f *fakeManager) unregister(Daemon) error {
	f.unregisters++
	f.registered_ = false
	if f.ln != nil {
		f.ln.Close()
		f.ln = nil
	}
	return nil
}

// shortDir is a temp directory with a short path. A Unix socket path is
// capped at about a hundred bytes on macOS, and t.TempDir() under a long test
// name goes past it — which fails as "bind: invalid argument" and says nothing
// about why.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func withManager(t *testing.T, m manager, ok bool) {
	t.Helper()
	old := findManager
	findManager = func(Daemon) (manager, bool) { return m, ok }
	t.Cleanup(func() { findManager = old })
}

// With a manager present, Start registers the daemon rather than spawning it,
// and Stop takes the registration away — so `makima up` survives a reboot and
// `makima down` means down until asked again.
func TestStartAndStopGoThroughTheManager(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "m.sock")
	bin := helperDaemon(t, sock)
	fm := &fakeManager{}
	withManager(t, fm, true)

	d := Daemon{Name: bin, Args: []string{sock}, Socket: sock, PIDFile: filepath.Join(dir, "m.pid"), Service: Service{Label: "test"}}
	ctx := context.Background()

	if err := d.Start(ctx, 5*time.Second); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if fm.registers != 1 {
		t.Fatalf("registered %d times, want 1", fm.registers)
	}
	if _, ok := d.readPID(); ok {
		t.Fatal("a manager-started daemon must not get a pidfile: the pid is not ours to signal")
	}
	if !d.Running() {
		t.Fatal("not running after Start")
	}

	// Again: idempotent, and no second registration.
	if err := d.Start(ctx, 5*time.Second); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	if fm.registers != 1 {
		t.Fatalf("a running daemon was registered again (%d)", fm.registers)
	}

	if err := d.Stop(ctx, 5*time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if fm.unregisters != 1 {
		t.Fatalf("unregistered %d times, want 1", fm.unregisters)
	}
	if d.Running() {
		t.Fatal("still running after Stop")
	}
}

// A manager that refuses is a note, not a failure: the daemon is started
// directly, exactly as on a machine with no manager at all.
func TestStartFallsBackWhenTheManagerRefuses(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "f.sock")
	bin := helperDaemon(t, sock)
	fm := &fakeManager{registerErr: errors.New("bootstrap failed: 5: Input/output error")}
	withManager(t, fm, true)

	d := Daemon{Name: bin, Args: []string{sock}, Socket: sock, PIDFile: filepath.Join(dir, "f.pid"), Service: Service{Label: "test"}}
	ctx := context.Background()

	if err := d.Start(ctx, 10*time.Second); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !d.Running() {
		t.Fatal("not running after the fallback")
	}
	if _, ok := d.readPID(); !ok {
		t.Fatal("the fallback spawn recorded no pid")
	}
	if err := d.Stop(ctx, 10*time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if d.Running() {
		t.Fatal("still running after Stop")
	}
}

// A registration that never answers is taken back, so the machine is not
// left with a service definition for something that does not work.
func TestStartUnregistersWhatNeverCameUp(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "n.sock")

	// A manager whose register only flips a flag: the definition is
	// "installed", and nothing ever answers on the socket.
	flag := &flagOnlyManager{}
	withManager(t, flag, true)

	d := Daemon{Name: "sh", Socket: sock, Service: Service{Label: "test"}, LogFile: filepath.Join(dir, "n.log")}
	err := d.Start(context.Background(), 300*time.Millisecond)
	if err == nil {
		t.Fatal("Start succeeded with nothing answering")
	}
	if !strings.Contains(err.Error(), "did not come up") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !flag.unregistered {
		t.Fatal("the dead registration was left in place")
	}
}

type flagOnlyManager struct{ registered_, unregistered bool }

func (f *flagOnlyManager) name() string                  { return "flag" }
func (f *flagOnlyManager) registered(Daemon) bool        { return f.registered_ }
func (f *flagOnlyManager) register(Daemon, string) error { f.registered_ = true; return nil }
func (f *flagOnlyManager) unregister(Daemon) error {
	f.unregistered = true
	f.registered_ = false
	return nil
}

// Stop on a daemon the manager registered but somebody else is actually
// running — an older makima started it by hand — still stops it.
func TestStopFallsThroughToTheProcessWhenTheManagerDidNotHaveIt(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "h.sock")
	bin := helperDaemon(t, sock)

	// Started directly, with no manager in the picture.
	withManager(t, nil, false)
	d := Daemon{Name: bin, Args: []string{sock}, Socket: sock, PIDFile: filepath.Join(dir, "h.pid"), Service: Service{Label: "test"}}
	if err := d.Start(context.Background(), 10*time.Second); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Now a manager appears that believes it owns the daemon but cannot
	// stop it.
	withManager(t, &flagOnlyManager{registered_: true}, true)
	if err := d.Stop(context.Background(), 10*time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if d.Running() {
		t.Fatal("the daemon outlived Stop")
	}
}

// Nobody but root can use a real manager, and the platform lookup says so
// rather than failing later inside launchctl or systemctl.
func TestPlatformManagerNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	d := Daemon{Name: "x", Service: Service{Label: "sh.makima.test", Unit: "makima-test"}}
	if _, ok := platformManager(d); ok {
		t.Fatal("a non-root process was offered the service manager")
	}
}

func TestLaunchdPlist(t *testing.T) {
	d := Daemon{
		Name:    "makimad",
		Args:    []string{"-config", "/etc/makima/node.json"},
		LogFile: "/var/log/makima/makimad.log",
		Service: Service{Label: "sh.makima.makimad"},
		Env:     map[string]string{"MAKIMA_OWNER": "ann", "B": "x<y&z"},
	}
	got := launchdPlist(d, "/Applications/makima.app/Contents/MacOS/makimad")

	for _, want := range []string{
		"<key>Label</key>\n  <string>sh.makima.makimad</string>",
		"<string>/Applications/makima.app/Contents/MacOS/makimad</string>",
		"<string>-config</string>",
		"<string>/etc/makima/node.json</string>",
		"<key>RunAtLoad</key>\n  <true/>",
		"<key>KeepAlive</key>\n  <true/>",
		"<key>ExitTimeOut</key>",
		"<key>StandardOutPath</key>\n  <string>/var/log/makima/makimad.log</string>",
		"<key>StandardErrorPath</key>",
		"<key>MAKIMA_OWNER</key>\n    <string>ann</string>",
		// Escaped, so a value with markup in it cannot break the file.
		"<key>B</key>\n    <string>x&lt;y&amp;z</string>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("plist lacks %q:\n%s", want, got)
		}
	}
	// Environment comes out sorted, so the file is the same every time.
	if strings.Index(got, "<key>B</key>") > strings.Index(got, "<key>MAKIMA_OWNER</key>") {
		t.Error("environment keys are not sorted")
	}
}

func TestSystemdUnit(t *testing.T) {
	d := Daemon{
		Name:    "makimad",
		Args:    []string{"-config", "/etc/makima/node.json"},
		LogFile: "/var/log/makima/makimad.log",
		Service: Service{Unit: "makimad", Description: "makima node daemon"},
		Env:     map[string]string{"MAKIMA_OWNER": "ann"},
	}
	got := systemdUnit(d, "/usr/local/bin/makimad")

	for _, want := range []string{
		"[Unit]\nDescription=makima node daemon\n",
		"After=network-online.target",
		"ExecStart=/usr/local/bin/makimad -config /etc/makima/node.json\n",
		"Environment=MAKIMA_OWNER=ann\n",
		"Restart=always",
		"KillSignal=SIGTERM",
		"StandardOutput=append:/var/log/makima/makimad.log",
		"[Install]\nWantedBy=multi-user.target",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("unit lacks %q:\n%s", want, got)
		}
	}
}

// A path with a space in it — an app bundle under "Application Support", a
// home directory with a name in it — has to survive systemd's parser.
func TestSystemdQuote(t *testing.T) {
	for given, want := range map[string]string{
		"/usr/local/bin/makimad": "/usr/local/bin/makimad",
		"/opt/my apps/makimad":   `"/opt/my apps/makimad"`,
		`say "hi"`:               `"say \"hi\""`,
		`back\slash`:             `"back\\slash"`,
		"":                       `""`,
		"MAKIMA_OWNER=ann":       "MAKIMA_OWNER=ann",
		"MAKIMA_OWNER=ann smith": `"MAKIMA_OWNER=ann smith"`,
	} {
		if got := systemdQuote(given); got != want {
			t.Errorf("systemdQuote(%q) = %s, want %s", given, got, want)
		}
	}
}

// Env reaches a directly spawned daemon too, not only the service file.
func TestSpawnPassesEnv(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "e.sock")
	bin := helperDaemon(t, sock)
	withManager(t, nil, false)

	d := Daemon{Name: bin, Args: []string{sock}, Socket: sock, PIDFile: filepath.Join(dir, "e.pid"), Env: map[string]string{"MAKIMA_TEST_ENV": "yes"}}
	got := d.envList()
	if len(got) != 1 || got[0] != "MAKIMA_TEST_ENV=yes" {
		t.Fatalf("envList = %v", got)
	}
	if err := d.Start(context.Background(), 10*time.Second); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_ = d.Stop(context.Background(), 10*time.Second)
}

// The plist has to be one launchd will load, and plutil is the judge of that
// on any Mac. Elsewhere there is nothing to ask.
func TestLaunchdPlistIsValid(t *testing.T) {
	plutil, err := exec.LookPath("plutil")
	if err != nil {
		t.Skip("no plutil here")
	}
	d := Daemon{
		Name:    "makimad",
		Args:    []string{"-config", "/etc/makima/node.json"},
		LogFile: "/var/log/makima/makimad.log",
		Service: Service{Label: "sh.makima.makimad"},
		Env:     map[string]string{"MAKIMA_OWNER": "ann"},
	}
	path := filepath.Join(t.TempDir(), "sh.makima.makimad.plist")
	if err := os.WriteFile(path, []byte(launchdPlist(d, "/usr/local/bin/makimad")), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(plutil, "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint: %v\n%s", err, out)
	}
}
