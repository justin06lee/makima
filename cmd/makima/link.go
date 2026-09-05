package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/justin06lee/makima/internal/supervise"
)

// Putting the command line where a shell can find it.
//
// The desktop app carries all four binaries inside its bundle and runs them
// from there, which is what makes "download it and click Connect" work with
// nothing else installed. But the person who did that will open a terminal
// within the hour and type `makima ssh desktop`, and it should work. So the
// first time the app brings a tunnel up, the CLI links itself into
// /usr/local/bin — the same thing Tailscale's app offers as a setting, done
// without asking because the app has already asked for root and nothing about
// a symlink is worth a second prompt.

// linkDir is where the links go. On PATH for every shell on macOS and Linux
// out of the box, and where `make install` puts the binaries anyway.
const linkDir = "/usr/local/bin"

// linkCmd is `makima link-cli`, for doing it on purpose.
func linkCmd(args []string) error {
	fs := flag.NewFlagSet("link-cli", flag.ExitOnError)
	quiet := fs.Bool("q", false, "say nothing unless something is wrong")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := mustBeRoot(); err != nil {
		return err
	}
	linked, err := linkCLI()
	if err != nil {
		return err
	}
	if !*quiet {
		if len(linked) == 0 {
			fmt.Printf("makima is already on PATH at %s.\n", linkDir)
		} else {
			fmt.Printf("Linked %s into %s. Open a new terminal and type: makima status\n", strings.Join(linked, ", "), linkDir)
		}
	}
	return nil
}

// linkCLI makes the running binary, and the daemons beside it, reachable by
// name. It reports which names it linked.
//
// It only ever touches a name that is absent or is already a symlink — a real
// file in /usr/local/bin is somebody's install, Homebrew's or make's, and is
// never replaced. Run as root, and only from somewhere other than linkDir,
// since linking a binary to itself is nothing.
func linkCLI() ([]string, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return linkInto(linkDir, self)
}

// linkInto does the linking for one directory and one binary, so it can be
// tried on a temporary directory rather than the real one.
func linkInto(dir, self string) ([]string, error) {
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	if filepath.Dir(self) == dir {
		return nil, nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("make %s: %w", dir, err)
	}

	var linked []string
	for _, name := range []string{"makima", "makimad", "makima-server", "makima-relay"} {
		target := self
		if name != "makima" {
			// The daemons live beside the CLI; Locate finds them there or
			// nowhere useful, so a miss is skipped rather than linked to a
			// copy from some other install.
			t, err := supervise.Locate(name)
			if err != nil || filepath.Dir(t) != filepath.Dir(self) {
				continue
			}
			target = t
		}

		link := filepath.Join(dir, name)
		fi, err := os.Lstat(link)
		switch {
		case err == nil && fi.Mode()&os.ModeSymlink == 0:
			// A real binary. Leave it alone.
			continue
		case err == nil:
			if existing, err := os.Readlink(link); err == nil && existing == target {
				continue
			}
			if err := os.Remove(link); err != nil {
				return linked, fmt.Errorf("replace %s: %w", link, err)
			}
		case !errors.Is(err, os.ErrNotExist):
			return linked, err
		}

		if err := os.Symlink(target, link); err != nil {
			return linked, fmt.Errorf("link %s: %w", link, err)
		}
		linked = append(linked, name)
	}
	return linked, nil
}

// linkCLIQuietly is what `up` and `join` do on the way out: link if there is
// nothing on PATH yet, say so in one line, and never fail the command over it.
func linkCLIQuietly() {
	if os.Geteuid() != 0 {
		return
	}
	linked, err := linkCLI()
	if err != nil || len(linked) == 0 {
		return
	}
	fmt.Printf("\nThe makima command is now on PATH, at %s/makima.\n", linkDir)
}
