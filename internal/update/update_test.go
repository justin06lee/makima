package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/update/updatetest"
	"github.com/justin06lee/subaru"
)

type release = updatetest.Release

func script(version string) string { return updatetest.Script(version) }

func suite(version string) map[string]string { return updatetest.Suite(version, Programs...) }

func fakeGitHub(t *testing.T, releases ...release) []subaru.Option {
	return updatetest.Serve(t, releases...)
}

// machine is an installed makima: the daemon's own directory, a second place
// copies live (an app bundle, /usr/local/bin), and the state directory.
type machine struct {
	self, other, state string
}

func install(t *testing.T, version string) machine {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in programs are shell scripts")
	}
	m := machine{self: t.TempDir(), other: t.TempDir(), state: t.TempDir()}
	for _, p := range Programs {
		write(t, filepath.Join(m.self, p), script(version))
	}
	// The other place has the CLI and the daemon only.
	write(t, filepath.Join(m.other, "makima"), script(version))
	write(t, filepath.Join(m.other, "makimad"), script(version))
	return m
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (m machine) installer(running string, opts []subaru.Option) *Installer {
	return &Installer{
		Running:  running,
		Self:     filepath.Join(m.self, "makimad"),
		StateDir: m.state,
		Options:  opts,
		Dirs:     []string{m.other},
	}
}

func (m machine) all() []string {
	var out []string
	for _, p := range Programs {
		out = append(out, filepath.Join(m.self, p))
	}
	return append(out, filepath.Join(m.other, "makima"), filepath.Join(m.other, "makimad"))
}

func TestInstallReplacesEveryCopyAndKeepsTheOldOnes(t *testing.T) {
	gh := fakeGitHub(t, release{Tag: "v0.3.0", Files: suite("v0.3.0")})
	m := install(t, "v0.2.0-60-gade5e2c")
	in := m.installer("v0.2.0-60-gade5e2c", gh)

	if err := in.Install(context.Background(), "v0.3.0", 7); err != nil {
		t.Fatal(err)
	}
	for _, p := range m.all() {
		if got := read(t, p); got != script("v0.3.0") {
			t.Errorf("%s = %q", p, got)
		}
		if got := read(t, p+".previous"); got != script("v0.2.0-60-gade5e2c") {
			t.Errorf("%s.previous = %q", p, got)
		}
	}
	p := in.Pending()
	if p == nil || p.To != "v0.3.0" || p.Order != 7 || len(p.Files) != 6 {
		t.Fatalf("pending = %+v", p)
	}

	// The new daemon starts, reaches its control plane, and settles.
	next := m.installer("v0.3.0", gh)
	if out, err := next.Starting(); err != nil || out != Trying {
		t.Fatalf("Starting = %v, %v", out, err)
	}
	if err := next.Settle(); err != nil {
		t.Fatal(err)
	}
	for _, p := range m.all() {
		if _, err := os.Stat(p + ".previous"); !os.IsNotExist(err) {
			t.Errorf("%s.previous survived settling", p)
		}
	}
	if next.Pending() != nil || !next.Handled(7) || next.Handled(8) {
		t.Errorf("after settling: pending %+v, handled 7 %v, handled 8 %v", next.Pending(), next.Handled(7), next.Handled(8))
	}
}

// Whoever asks, a machine does not go backwards.
func TestInstallRefusesAnOlderOrEqualRelease(t *testing.T) {
	gh := fakeGitHub(t, release{Tag: "v0.3.0", Files: suite("v0.3.0")})
	for _, running := range []string{"v0.3.0", "v0.3.0-4-gabc1234", "v0.4.0"} {
		m := install(t, running)
		err := m.installer(running, gh).Install(context.Background(), "v0.3.0", 1)
		if !errors.Is(err, ErrNotNewer) {
			t.Errorf("running %s: err = %v", running, err)
		}
		if got := read(t, filepath.Join(m.self, "makimad")); got != script(running) {
			t.Errorf("running %s: makimad replaced", running)
		}
	}
}

// A daemon that will not run here — or that is not the release it claims to
// be — is found out before anything is replaced.
func TestInstallDryRunsTheNewDaemonFirst(t *testing.T) {
	broken := suite("v0.3.0")
	broken["makimad"] = "#!/bin/sh\nexit 3\n"
	liar := suite("v0.3.0")
	liar["makimad"] = script("v0.2.9")

	for name, files := range map[string]map[string]string{"will not run": broken, "wrong version": liar} {
		t.Run(name, func(t *testing.T) {
			gh := fakeGitHub(t, release{Tag: "v0.3.0", Files: files})
			m := install(t, "v0.2.0")
			err := m.installer("v0.2.0", gh).Install(context.Background(), "v0.3.0", 1)
			if err == nil || !strings.Contains(err.Error(), "new makimad") {
				t.Fatalf("err = %v", err)
			}
			for _, p := range m.all() {
				if got := read(t, p); got != script("v0.2.0") {
					t.Errorf("%s replaced", p)
				}
			}
			for _, dir := range []string{m.self, m.other} {
				entries, _ := os.ReadDir(dir)
				for _, e := range entries {
					if strings.Contains(e.Name(), ".subaru-") || strings.HasSuffix(e.Name(), ".previous") {
						t.Errorf("left behind %s", e.Name())
					}
				}
			}
		})
	}
}

// The new version gets a few starts to settle. A daemon that keeps dying on
// the way up — launchd and systemd restart it straight back into the same
// code — has the old files put back, and says why.
func TestAVersionThatWillNotStayUpIsRolledBack(t *testing.T) {
	gh := fakeGitHub(t, release{Tag: "v0.3.0", Files: suite("v0.3.0")})
	m := install(t, "v0.2.0")
	if err := m.installer("v0.2.0", gh).Install(context.Background(), "v0.3.0", 4); err != nil {
		t.Fatal(err)
	}

	next := m.installer("v0.3.0", gh)
	for i := 1; i <= maxStarts; i++ {
		if out, err := next.Starting(); err != nil || out != Trying {
			t.Fatalf("start %d: %v, %v", i, out, err)
		}
	}
	out, err := next.Starting()
	if err != nil || out != RolledBack {
		t.Fatalf("start %d: %v, %v", maxStarts+1, out, err)
	}
	for _, p := range m.all() {
		if got := read(t, p); got != script("v0.2.0") {
			t.Errorf("%s = %q after rolling back", p, got)
		}
	}

	old := m.installer("v0.2.0", gh)
	f := old.Failed()
	if f == nil || f.Tag != "v0.3.0" || !strings.Contains(f.Error, "went back to v0.2.0") {
		t.Fatalf("failure = %+v", f)
	}
	if !old.Handled(4) {
		t.Error("the order that failed would be tried again")
	}
	if out, _ := old.Starting(); out != Nothing {
		t.Errorf("the old version starting found %v", out)
	}
}

// Somebody ran make install with something else while an update was
// pending: that is what the machine runs now.
func TestAnotherVersionArrivingEndsThePendingUpdate(t *testing.T) {
	gh := fakeGitHub(t, release{Tag: "v0.3.0", Files: suite("v0.3.0")})
	m := install(t, "v0.2.0")
	if err := m.installer("v0.2.0", gh).Install(context.Background(), "v0.3.0", 1); err != nil {
		t.Fatal(err)
	}
	other := m.installer("v0.3.1-2-g1234567", gh)
	if out, err := other.Starting(); err != nil || out != Nothing {
		t.Fatalf("Starting = %v, %v", out, err)
	}
	if other.Pending() != nil {
		t.Error("the pending update was kept")
	}
	if _, err := os.Stat(filepath.Join(m.self, "makimad.previous")); !os.IsNotExist(err) {
		t.Error("the old files were kept")
	}
}

func TestTargetsFollowSymlinksOnce(t *testing.T) {
	m := install(t, "v0.2.0")
	link := t.TempDir()
	if err := os.Symlink(filepath.Join(m.self, "makima"), filepath.Join(link, "makima")); err != nil {
		t.Fatal(err)
	}
	in := &Installer{Self: filepath.Join(m.self, "makimad"), Dirs: []string{link, m.other}}
	got := in.Targets()
	if len(got["makima"]) != 2 {
		t.Errorf("makima copies = %v, want the real file once and the other copy", got["makima"])
	}
	for _, p := range got["makima"] {
		if strings.HasPrefix(p, link) {
			t.Errorf("the symlink itself is a target: %s", p)
		}
	}
	if len(got["makima-relay"]) != 1 {
		t.Errorf("makima-relay copies = %v", got["makima-relay"])
	}
}

func TestLatestSaysWhenThereIsNoRelease(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	_, err := Latest(context.Background(), "v0.2.0", subaru.WithAPIBase(srv.URL), subaru.WithHTTPClient(srv.Client()))
	if err == nil || !strings.Contains(err.Error(), "no published release") {
		t.Fatalf("err = %v", err)
	}

	gh := fakeGitHub(t, release{Tag: "v0.3.0", Files: suite("v0.3.0")}, release{Tag: "v0.3.1", Files: suite("v0.3.1")})
	if tag, err := Latest(context.Background(), "v0.2.0", gh...); err != nil || tag != "v0.3.1" {
		t.Fatalf("Latest = %q, %v", tag, err)
	}
}

func TestWatchExecutableNoticesAReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "makima-server")
	write(t, exe, script("v0.2.0"))

	fired := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchExecutable(ctx, exe, 20*time.Millisecond, []string{"version"}, func() { close(fired) })

	// A replacement that will not run is not acted on.
	time.Sleep(60 * time.Millisecond)
	tmp := filepath.Join(dir, ".new")
	write(t, tmp, "#!/bin/sh\nexit 1\n")
	os.Rename(tmp, exe)
	select {
	case <-fired:
		t.Fatal("fired for a binary that does not run")
	case <-time.After(200 * time.Millisecond):
	}

	write(t, tmp, script("v0.3.0"))
	os.Rename(tmp, exe)
	select {
	case <-fired:
	case <-time.After(5 * time.Second):
		t.Fatal("never noticed the new binary")
	}
}

func TestAPackageManagersFilesAreLeftToIt(t *testing.T) {
	for _, p := range []string{"/opt/homebrew/Cellar/makima/0.2.0/bin/makimad", "/nix/store/abc-makima/bin/makimad"} {
		if err := managed(map[string][]string{"makimad": {p}}); err == nil {
			t.Errorf("%s would be replaced", p)
		}
	}
	if err := managed(map[string][]string{"makimad": {"/usr/local/bin/makimad"}}); err != nil {
		t.Errorf("/usr/local/bin refused: %v", err)
	}
}

// Order numbers are a network's own and start at one again on another. A
// machine that left one network for another used to ignore every order the
// new one gave until its numbers passed the old one's.
func TestAnotherNetworksOrdersAreNotHandledAlready(t *testing.T) {
	dir := t.TempDir()
	home := &Installer{StateDir: dir, Network: "network-a"}
	if err := home.MarkHandled(7, "v0.3.0", errors.New("no")); err != nil {
		t.Fatal(err)
	}
	if !home.Handled(1) || home.Failed() == nil {
		t.Fatal("the first network's record did not stick")
	}

	moved := &Installer{StateDir: dir, Network: "network-b"}
	if moved.Handled(1) {
		t.Error("the new network's first order counts as handled because of the old network's seventh")
	}
	if moved.Failed() != nil {
		t.Error("the old network's failure is reported to the new one")
	}
}

// The same network, read again, keeps its record — the daemon reads it on
// every start, and losing it would retry a failed order on every restart.
func TestTheSameNetworksRecordSurvives(t *testing.T) {
	dir := t.TempDir()
	a := &Installer{StateDir: dir, Network: "network-a"}
	if err := a.MarkHandled(3, "v0.3.0", nil); err != nil {
		t.Fatal(err)
	}
	again := &Installer{StateDir: dir, Network: "network-a"}
	if !again.Handled(3) {
		t.Error("the record was lost between two reads for the same network")
	}
}
