package update

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

// Self is this program's own path, symlinks resolved: after an update
// replaces the file, it is where the new one is.
func Self() string {
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		return real
	}
	return exe
}

// WatchExecutable calls replaced once the file at path has been replaced by
// one that runs, and then returns.
//
// For the programs that do not restart themselves after an update — the
// control plane, and the relay — so that swapping their binary is all it
// takes to have them run the new one. A file that changed but will not run
// with args is ignored until it changes again.
func WatchExecutable(ctx context.Context, path string, every time.Duration, args []string, replaced func()) {
	was, err := os.Stat(path)
	if err != nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now, err := os.Stat(path)
		if err != nil || sameFile(was, now) {
			continue
		}
		was = now
		if _, err := runProgram(ctx, path, args...); err != nil {
			continue
		}
		replaced()
		return
	}
}

func sameFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
