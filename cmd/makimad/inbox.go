package main

import (
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/drop"
)

// Receiving files, from the daemon's side.
//
// The inbox is on by default, which is a deliberate choice and the same one
// auto-serve makes: a mesh is trusted like this machine is, and a feature that
// has to be discovered and switched on before it works is a feature most
// people never find. The safety is in what a sender can do rather than in
// whether it can do anything — one directory, base names only, no overwrites,
// a size cap, and files nobody but their owner can read.

// defaultInboxDir is where files land when nothing says otherwise.
//
// Under the invoking user's home when there is one, because a file that
// arrives somewhere you cannot find is barely better than one that did not
// arrive. Falling back to the daemon's own state directory on a machine with
// no interactive user — a server — where a home directory would be a worse
// guess than an obvious system path.
func defaultInboxDir() (string, *drop.Owner) {
	if home, u, ok := invokingUser(); ok {
		return filepath.Join(home, "Downloads", "makima"), u
	}
	return "/var/lib/makima/inbox", nil
}

// invokingUser finds the human behind a sudo, and their home and IDs.
//
// The daemon runs as root because it holds a TUN device. Files it creates
// would therefore be root-owned inside somebody's home directory, where they
// could not be deleted without sudo — a small thing that makes the whole
// feature feel broken.
func invokingUser() (home string, owner *drop.Owner, ok bool) {
	u := invoker()
	if u == nil {
		// Nobody behind us. If the daemon is genuinely running as a person,
		// their own home is the right answer.
		if os.Geteuid() != 0 {
			if h, err := os.UserHomeDir(); err == nil {
				return h, nil, true
			}
		}
		return "", nil, false
	}
	if u.HomeDir == "" {
		return "", nil, false
	}

	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return u.HomeDir, nil, true
	}
	return u.HomeDir, &drop.Owner{UID: uid, GID: gid}, true
}

// invoker is the person makima is running on behalf of, or nil.
//
// Four ways to learn it, tried in the order of how directly each one says so:
//
//   - SUDO_USER — `sudo makima up` in a terminal, the common case.
//   - PKEXEC_UID — polkit, which is how the Linux desktop app asks for root.
//     pkexec scrubs the environment and sets this one variable in its place.
//   - MAKIMA_OWNER — set on purpose by whatever launched us. The macOS app's
//     admin prompt runs a shell with none of the above in it, so the app says
//     who it is running for explicitly. A uid or a username.
//   - The owner of /dev/console — whoever is logged in at the screen on a
//     Mac. The last resort, for a daemon a launchd job started.
//
// Root itself never counts: a root-owned socket in a root-owned directory is
// what the daemon has anyway, and the point here is to find a person.
func invoker() *user.User {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if u, err := user.Lookup(name); err == nil {
			return u
		}
	}
	if uid := os.Getenv("PKEXEC_UID"); uid != "" && uid != "0" {
		if u, err := user.LookupId(uid); err == nil {
			return u
		}
	}
	if who := os.Getenv("MAKIMA_OWNER"); who != "" && who != "root" && who != "0" {
		if u, err := user.LookupId(who); err == nil {
			return u
		}
		if u, err := user.Lookup(who); err == nil {
			return u
		}
	}
	if uid, ok := consoleUID(); ok {
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			return u
		}
	}
	return nil
}

// inboxConfig resolves the flags and the stored settings into what the
// receiver should actually do.
//
// Flags win over the configuration, and both lose to -no-recv. That ordering
// is what makes `makimad -no-recv` a reliable way to be certain, rather than
// something a stale config file can quietly undo.
func (n *node) inboxConfig(opts options) drop.Config {
	if opts.noRecv {
		return drop.Config{}
	}

	n.mu.Lock()
	stored, off := n.file.Inbox, n.file.InboxOff
	n.mu.Unlock()

	if off {
		return drop.Config{}
	}

	dir, owner := defaultInboxDir()
	if stored != "" {
		dir = stored
		// A directory chosen by hand may be anywhere, so the ownership guess
		// no longer applies unless it is under the same user's home.
		if home, u, ok := invokingUser(); ok && isUnder(dir, home) {
			owner = u
		} else {
			owner = nil
		}
	}
	if opts.inbox != "" {
		dir = opts.inbox
		owner = nil
	}

	return drop.Config{Dir: dir, Owner: owner, MaxSize: opts.maxFile}
}

// isUnder reports whether path sits inside dir.
func isUnder(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != ".." && !filepath.HasPrefix(rel, ".."+string(filepath.Separator))
}

// applyInbox binds or rebinds the receiver to the current mesh address.
func (n *node) applyInbox() {
	if n.inbox == nil {
		return
	}
	n.inbox.Apply(n.meshAddr(), n.inboxConfig(n.opts))
}

// SetInbox changes where received files land, or switches receiving off.
func (n *node) SetInbox(dir string, off bool) error {
	n.mu.Lock()
	n.file.Inbox = dir
	n.file.InboxOff = off
	err := conf.Save(n.cfgPath, n.file)
	n.mu.Unlock()

	if err != nil {
		return err
	}
	n.applyInbox()

	if off {
		log.Print("inbox: off — this machine no longer accepts files")
	}
	return nil
}
