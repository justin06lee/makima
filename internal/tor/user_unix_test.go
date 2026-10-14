//go:build !windows

package tor

import (
	"os"
	"path/filepath"
	"testing"
)

// A root makima's tor runs as nobody, so a data directory inside one of
// makima's own root-only directories is out of its reach.
func TestClosedDirectoryOnTheWayIsFound(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(base, "private")
	open := filepath.Join(base, "open")
	for d, mode := range map[string]os.FileMode{private: 0o700, open: 0o755} {
		if err := os.Mkdir(d, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
	}
	// The temporary directory's own ancestors may be closed on this machine;
	// what is asserted is only what changes between the two.
	baseClosed, err := closedAncestor(filepath.Join(base, "x"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := closedAncestor(filepath.Join(private, "tor"))
	if err != nil {
		t.Fatal(err)
	}
	if got != private {
		t.Errorf("closedAncestor under a 0700 directory = %q, want %q", got, private)
	}
	got, err = closedAncestor(filepath.Join(open, "tor"))
	if err != nil {
		t.Fatal(err)
	}
	if got != baseClosed {
		t.Errorf("closedAncestor under a 0755 directory = %q, want %q", got, baseClosed)
	}
}

func TestDataDirIsBesideItsOwnerWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	if got := DataDir("/home/me/.config/makima/node.json"); got != "/home/me/.config/makima/tor" {
		t.Errorf("DataDir = %s", got)
	}
}
