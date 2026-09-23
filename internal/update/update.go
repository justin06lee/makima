// Package update moves one machine's makima to a published release, and
// undoes it if the new version will not run.
//
// The release comes from the project's GitHub releases through subaru: one
// archive per platform holding all four programs, checked against the
// SHA256SUMS published beside it before anything is unpacked. Every copy of
// every program on the machine is replaced together — the daemon may run from
// inside the desktop app's bundle while the CLI is in /usr/local/bin, and
// leaving either on the old release would mean two versions talking to each
// other — and the new daemon is run once, off to the side, before any of them
// is.
//
// What it will not do is go backwards. A release older than the one running
// is refused, whoever asked for it, so the most anybody can do by asking a
// machine to update is move it forward to something the project published.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/justin06lee/subaru"
)

// Repo is where makima is released.
const Repo = "justin06lee/makima"

// Programs are the binaries a release carries, all of which move together.
var Programs = []string{"makima", "makimad", "makima-server", "makima-relay"}

// maxStarts is how many times a new version may start without settling
// before the old one is put back. A daemon that dies on the way up is
// restarted by launchd or systemd, and each restart counts.
const maxStarts = 3

// ErrNotNewer is a release that is not newer than what is running.
var ErrNotNewer = errors.New("that release is not newer than this machine's")

// Latest is the newest published release.
func Latest(ctx context.Context, running string, opts ...subaru.Option) (string, error) {
	rel, err := newUpdater(running, opts).Check(ctx)
	if err != nil {
		if errors.Is(err, subaru.ErrNoRelease) {
			return "", errors.New("makima has no published release yet")
		}
		return "", err
	}
	return rel.Tag, nil
}

func newUpdater(running string, opts []subaru.Option) *subaru.Updater {
	base := []subaru.Option{
		subaru.WithName("makima"),
		subaru.WithVersion(running),
		subaru.WithPolicy(subaru.Off),
		subaru.WithRequireChecksum(true),
		subaru.WithTimeout(30 * time.Second),
	}
	return subaru.New(Repo, append(base, opts...)...)
}

// Installer moves this machine to a release.
type Installer struct {
	// Running is this build's version.
	Running string

	// Self is the running daemon's own path, symlinks resolved. Its
	// directory is searched first, and it is what is started again.
	Self string

	// StateDir is where the update's record is kept, beside the node's
	// configuration.
	StateDir string

	// Options are passed to subaru; tests point it at a fake GitHub.
	Options []subaru.Option

	// Dirs, when set, replaces the places copies are looked for beside
	// Self's own directory. Tests use it; the defaults are in dirs.
	Dirs []string

	// Run runs a program and returns what it printed; the dry run of a new
	// daemon goes through it. Nil means actually run it.
	Run func(ctx context.Context, path string, args ...string) (string, error)
}

// dirs is everywhere a copy of makima's programs may live.
//
// The daemon's own directory first. /usr/local/bin is where make install and
// the release archive's instructions put them. On a Mac the desktop app
// carries all four inside its bundle — and may run the daemon from there —
// and keeps root's own copy in /Library/PrivilegedHelperTools for its
// password-free buttons; that copy is compared with the bundle's by size and
// modification time, which is why every copy is written with the archive's
// timestamp.
func (in *Installer) dirs() []string {
	out := []string{filepath.Dir(in.Self)}
	extra := in.Dirs
	if extra == nil {
		extra = []string{"/usr/local/bin"}
		if runtime.GOOS == "darwin" {
			extra = append(extra, "/Library/PrivilegedHelperTools/makima", "/Applications/makima.app/Contents/MacOS")
		}
	}
	for _, d := range extra {
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// Targets finds every copy of every program on this machine, by name.
//
// A symlink is followed to the file it names, so a /usr/local/bin/makima that
// points into the app bundle is replaced once, where it points.
func (in *Installer) Targets() map[string][]string {
	out := make(map[string][]string)
	seen := make(map[string]bool)
	for _, dir := range in.dirs() {
		for _, name := range Programs {
			p := filepath.Join(dir, name)
			real, err := filepath.EvalSymlinks(p)
			if err != nil {
				continue
			}
			fi, err := os.Stat(real)
			if err != nil || !fi.Mode().IsRegular() || seen[real] {
				continue
			}
			seen[real] = true
			out[name] = append(out[name], real)
		}
	}
	return out
}

// Install moves this machine to the release tagged tag: downloads and checks
// it, dry-runs the new daemon, keeps the old files for going back, and swaps
// every copy in. It restarts nothing; the caller does, and the next start of
// the daemon counts against the new version's chances (see Starting).
func (in *Installer) Install(ctx context.Context, tag string, order uint64) error {
	u := newUpdater(in.Running, in.Options)
	rel, err := u.Release(ctx, tag)
	if err != nil {
		if errors.Is(err, subaru.ErrNoRelease) {
			return fmt.Errorf("makima has no release %s", tag)
		}
		return err
	}
	if !rel.Newer {
		return fmt.Errorf("%w (%s here, asked for %s)", ErrNotNewer, in.Running, tag)
	}

	targets := in.Targets()
	if len(targets["makimad"]) == 0 {
		return fmt.Errorf("found no makimad to replace (looked beside %s)", in.Self)
	}
	if err := managed(targets); err != nil {
		return err
	}
	staged, err := u.Stage(ctx, rel, targets)
	if err != nil {
		return err
	}
	defer staged.Discard()

	// The new daemon has to run on this machine and say it is the release
	// before anything it would replace is touched. That catches the wrong
	// architecture, a truncated file, a binary the OS refuses — every way a
	// new version could fail before it gets as far as its own main.
	run := in.Run
	if run == nil {
		run = runProgram
	}
	out, err := run(ctx, staged.Path("makimad"), "-version")
	if err != nil {
		return fmt.Errorf("the new makimad would not run here: %w", err)
	}
	if got := strings.TrimSpace(out); subaru.Canonical(got) != subaru.Canonical(tag) {
		return fmt.Errorf("the new makimad says it is %q, not %s", got, tag)
	}

	var files []string
	for _, paths := range targets {
		files = append(files, paths...)
	}
	slices.Sort(files)
	if err := keepPrevious(files); err != nil {
		dropPrevious(files)
		return err
	}
	st := in.load()
	st.Pending = &Pending{From: in.Running, To: rel.Tag, Order: order, Files: files, At: time.Now().UTC()}
	if err := in.save(st); err != nil {
		dropPrevious(files)
		return fmt.Errorf("record the update: %w", err)
	}
	if err := staged.Commit(); err != nil {
		st.Pending = nil
		_ = in.save(st)
		dropPrevious(files)
		return err
	}
	return nil
}

// managed refuses to replace files a package manager owns. Swapping them
// behind its back leaves it believing an older version is installed, and its
// next upgrade or uninstall acting on files that are not what it wrote.
func managed(targets map[string][]string) error {
	for _, paths := range targets {
		for _, p := range paths {
			switch {
			case strings.Contains(p, "/Cellar/"):
				return errors.New("makima here was installed by Homebrew; update it with: brew upgrade makima")
			case strings.HasPrefix(p, "/nix/store/"):
				return errors.New("makima here was installed by Nix; update it through Nix")
			}
		}
	}
	return nil
}

// Outcome is what Starting found.
type Outcome int

const (
	// Nothing: no update was waiting to be proven.
	Nothing Outcome = iota
	// Trying: this is a new version, not yet settled.
	Trying
	// RolledBack: the new version failed to settle too many times and the
	// old files are back. The caller must start again, as the old version.
	RolledBack
)

// Starting is called first thing when the daemon starts, and decides whether
// the version now running has had enough chances.
//
// Every start of the new version before it settles counts. A daemon that dies
// on the way up is restarted by launchd or systemd straight back into the
// same code, and after maxStarts of those the old files are put back — so a
// release that cannot run on some machine costs that machine a minute, not
// its place in the network.
func (in *Installer) Starting() (Outcome, error) {
	st := in.load()
	p := st.Pending
	if p == nil {
		return Nothing, nil
	}
	if subaru.Canonical(in.Running) != subaru.Canonical(p.To) {
		// Not the version that was swapped in. Whatever put this one here —
		// somebody's make install, an earlier rollback — it is what this
		// machine runs now, and the pending update is over.
		dropPrevious(p.Files)
		st.Pending = nil
		return Nothing, in.save(st)
	}
	p.Starts++
	if p.Starts <= maxStarts {
		return Trying, in.save(st)
	}

	if err := restorePrevious(p.Files); err != nil {
		return Trying, fmt.Errorf("put %s back: %w", p.From, err)
	}
	st.Failed = &Failure{Order: p.Order, Tag: p.To, Error: fmt.Sprintf("%s would not stay up here, so this machine went back to %s", p.To, p.From)}
	st.Handled = max(st.Handled, p.Order)
	st.Pending = nil
	return RolledBack, in.save(st)
}

// Settle records that the new version works: the old files go, and so does
// any earlier failure.
func (in *Installer) Settle() error {
	st := in.load()
	if st.Pending == nil {
		return nil
	}
	dropPrevious(st.Pending.Files)
	st.Handled = max(st.Handled, st.Pending.Order)
	st.Pending = nil
	st.Failed = nil
	return in.save(st)
}

// Handled reports whether an order has been acted on here already, so one
// that failed is not retried on every netmap.
func (in *Installer) Handled(order uint64) bool {
	return order <= in.load().Handled
}

// MarkHandled records an order acted on, with err saying why it failed or
// nil when there was nothing to do.
func (in *Installer) MarkHandled(order uint64, tag string, err error) error {
	st := in.load()
	st.Handled = max(st.Handled, order)
	if err != nil {
		st.Failed = &Failure{Order: order, Tag: tag, Error: err.Error()}
	}
	return in.save(st)
}

// Failed is the last update that failed here, if the machine has not moved
// on from it since.
func (in *Installer) Failed() *Failure {
	return in.load().Failed
}

// Pending is the update swapped in and not yet settled, if any.
func (in *Installer) Pending() *Pending {
	return in.load().Pending
}

// State is the update record, kept as update.json beside the node's
// configuration.
type State struct {
	// Handled is the last update order this machine acted on.
	Handled uint64 `json:"handled,omitempty"`

	// Failed is the last attempt that failed, reported to the network until
	// the machine updates successfully.
	Failed *Failure `json:"failed,omitempty"`

	// Pending is an update swapped in and not yet proven.
	Pending *Pending `json:"pending,omitempty"`
}

// Failure is one update that did not happen.
type Failure struct {
	Order uint64 `json:"order"`
	Tag   string `json:"tag"`
	Error string `json:"error"`
}

// Pending is an update whose new files are in place and whose old ones wait
// beside them, as NAME.previous, until the new version proves itself.
type Pending struct {
	From   string    `json:"from"`
	To     string    `json:"to"`
	Order  uint64    `json:"order"`
	Files  []string  `json:"files"`
	Starts int       `json:"starts"`
	At     time.Time `json:"at"`
}

func (in *Installer) statePath() string { return filepath.Join(in.StateDir, "update.json") }

func (in *Installer) load() State {
	var st State
	b, err := os.ReadFile(in.statePath())
	if err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func (in *Installer) save(st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(in.StateDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(in.StateDir, ".update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), in.statePath())
}

// keepPrevious leaves each file's current contents beside it as
// NAME.previous. A hard link where the filesystem allows one, since the swap
// that follows replaces the directory entry and leaves the old inode alone.
func keepPrevious(files []string) error {
	for _, f := range files {
		prev := f + ".previous"
		_ = os.Remove(prev)
		if err := os.Link(f, prev); err == nil {
			continue
		}
		if err := copyFile(f, prev); err != nil {
			return fmt.Errorf("keep a copy of %s: %w", f, err)
		}
	}
	return nil
}

func restorePrevious(files []string) error {
	var errs []error
	for _, f := range files {
		prev := f + ".previous"
		if _, err := os.Stat(prev); err != nil {
			continue
		}
		if err := os.Rename(prev, f); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func dropPrevious(files []string) {
	for _, f := range files {
		_ = os.Remove(f + ".previous")
	}
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, b, fi.Mode().Perm()); err != nil {
		return err
	}
	return os.Chtimes(dst, fi.ModTime(), fi.ModTime())
}

func runProgram(ctx context.Context, path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).Output()
	return string(out), err
}
