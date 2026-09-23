package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/update"
	"github.com/justin06lee/makima/internal/update/updatetest"
)

// running pretends this daemon was built as v.
func running(t *testing.T, v string) {
	t.Helper()
	was := version
	version = v
	t.Cleanup(func() { version = was })
}

// updatable is a daemon whose programs are stand-ins in a temporary
// directory, updating from a fake GitHub.
func updatable(t *testing.T, releases ...updatetest.Release) (*node, string, context.Context) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in programs are shell scripts")
	}
	dir, state := t.TempDir(), t.TempDir()
	for _, p := range update.Programs {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(updatetest.Script(version)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	n := &node{
		pollKick: make(chan struct{}, 1),
		stopRun:  stop,
		updater: &update.Installer{
			Running:  version,
			Self:     filepath.Join(dir, "makimad"),
			StateDir: state,
			Options:  updatetest.Serve(t, releases...),
			Dirs:     []string{},
		},
	}
	return n, dir, ctx
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The order arrives in a netmap; the daemon installs the release, says it is
// restarting, and ends its run so main starts the new binary in its place.
func TestAnOrderInstallsAndRestarts(t *testing.T) {
	running(t, "v0.2.0")
	n, dir, ctx := updatable(t, updatetest.Release{Tag: "v0.3.0", Files: updatetest.Suite("v0.3.0", update.Programs...)})

	n.considerUpdate(ctx, control.UpdateOrder{ID: 1, Tag: "v0.3.0", By: "laptop"})
	waitFor(t, "the restart", func() bool { return ctx.Err() != nil })

	if !n.restarting.Load() {
		t.Error("the run ended without saying it was a restart")
	}
	if s := n.updateStatus(); s == nil || s.State != netmap.UpdateRestarting || s.Tag != "v0.3.0" {
		t.Errorf("status = %+v", s)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "makimad"))
	if string(b) != updatetest.Script("v0.3.0") {
		t.Errorf("makimad = %q", b)
	}
	if p := n.updater.Pending(); p == nil || p.To != "v0.3.0" {
		t.Errorf("pending = %+v", p)
	}
}

// A release that is not there fails, says why, and is not tried again on
// every netmap — until somebody asks again.
func TestAFailedOrderIsReportedAndNotRetried(t *testing.T) {
	running(t, "v0.2.0")
	n, _, ctx := updatable(t, updatetest.Release{Tag: "v0.3.0", Files: updatetest.Suite("v0.3.0", update.Programs...)})

	n.considerUpdate(ctx, control.UpdateOrder{ID: 1, Tag: "v9.9.9"})
	waitFor(t, "the failure", func() bool {
		s := n.updateStatus()
		return s != nil && s.State == netmap.UpdateFailed
	})
	waitFor(t, "the attempt to end", func() bool { return !n.updating.Load() })
	if ctx.Err() != nil {
		t.Fatal("a failed update restarted the daemon")
	}
	if !n.updater.Handled(1) {
		t.Fatal("the failed order would be tried again")
	}

	n.considerUpdate(ctx, control.UpdateOrder{ID: 1, Tag: "v9.9.9"})
	if n.updating.Load() {
		t.Error("the same order started again")
	}

	n.considerUpdate(ctx, control.UpdateOrder{ID: 2, Tag: "v0.3.0"})
	waitFor(t, "the second order's restart", func() bool { return ctx.Err() != nil })
}

// A machine already on the release, or ahead of it on a development build,
// is left alone and says nothing.
func TestAnOrderForWhatIsAlreadyHereIsIgnored(t *testing.T) {
	for _, v := range []string{"v0.3.0", "v0.3.0-7-gabcdef0", "v0.4.0"} {
		running(t, v)
		n, _, ctx := updatable(t, updatetest.Release{Tag: "v0.3.0", Files: updatetest.Suite("v0.3.0", update.Programs...)})
		n.considerUpdate(ctx, control.UpdateOrder{ID: 5, Tag: "v0.3.0"})
		if n.updating.Load() || n.updateStatus() != nil {
			t.Errorf("%s: acted on an order for v0.3.0", v)
		}
		if !n.updater.Handled(5) {
			t.Errorf("%s: order not recorded as handled", v)
		}
	}
}
