package main

import (
	"log"
	"path/filepath"

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
// Under the owner's home when this machine has one, because a file that
// arrives somewhere you cannot find is barely better than one that did not
// arrive. Falling back to the daemon's own state directory on a machine with
// no owner — a server — where a home directory would be a worse guess than an
// obvious system path.
func defaultInboxDir(o *owner) (string, *drop.Owner) {
	if o == nil || o.Home == "" {
		return "/var/lib/makima/inbox", nil
	}
	return filepath.Join(o.Home, "Downloads", "makima"), &drop.Owner{UID: o.UID, GID: o.GID, Home: o.Home}
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

	own := n.owner()
	dir, owner := defaultInboxDir(own)
	if stored != "" {
		dir = stored
		// A directory chosen by hand may be anywhere, so the ownership guess
		// no longer applies unless it is under the same user's home.
		if own != nil && isUnder(dir, own.Home) {
			owner = &drop.Owner{UID: own.UID, GID: own.GID, Home: own.Home}
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
