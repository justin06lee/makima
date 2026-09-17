package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/sshd"
)

// Who this machine's makima belongs to.
//
// The daemon runs as root because it holds a TUN device, and almost everything
// it does on somebody's behalf needs to know whose behalf that is: which
// account may open the read-only socket the desktop app and every non-root
// tool read, whose Downloads received files land in, and which account a shell
// session runs as when the far end names none.
//
// The environment is the obvious place to learn it and the least durable one.
// SUDO_USER exists only under sudo, PKEXEC_UID only under polkit, and the
// console user only while somebody is logged in at the screen. A machine set
// up over SSH as root has none of them, and the daemon would then run with no
// owner at all — no desktop socket, no inbox in a home directory, sessions
// defaulting to root — with nothing in the log to say that had happened. So
// the answer is written into the config the first time anything knows it, and
// read back from there for the rest of the machine's life.

// owner is the account this node belongs to.
type owner struct {
	Name string
	UID  int
	GID  int
	Home string
}

// ownerFor resolves the account this node belongs to, and says where the
// answer came from.
//
// In order of how directly each source says so: the environment of whatever
// started us, the account written in the config by an earlier start, whoever
// is logged in at the screen, and — on a machine with exactly one — its only
// account. Root is never an answer: the point is to find a person, and root
// already has the socket that can change things.
func ownerFor(stored string) (*owner, string) {
	if u := envOwner(); u != nil {
		return accountOwner(u), "the environment"
	}
	if u := namedOwner(stored); u != nil {
		return accountOwner(u), "the configuration"
	}
	if uid, ok := consoleUID(); ok {
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			return accountOwner(u), "whoever is logged in at the screen"
		}
	}
	// A daemon that is genuinely running as a person is that person's. It
	// needs root for a TUN device and refuses to start without it, so this is
	// only reached in a build or a test that does without one.
	if os.Geteuid() != 0 {
		if u, err := user.Current(); err == nil && u.Uid != "0" {
			return accountOwner(u), "the account this daemon is running as"
		}
	}
	if o := soleAccount(); o != nil {
		return o, "the only account on this machine"
	}
	return nil, ""
}

// envOwner is the person behind this root, by whichever variable says so:
//
//   - SUDO_USER — `sudo makima up` in a terminal, the common case.
//   - PKEXEC_UID — polkit, which is how the Linux desktop app asks for root.
//     pkexec scrubs the environment and sets this one variable in its place.
//   - MAKIMA_OWNER — set on purpose by whatever launched us. The macOS app's
//     admin prompt runs a shell with none of the above in it, so the app says
//     who it is running for explicitly. A uid or a username.
func envOwner() *user.User {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if u, err := user.Lookup(name); err == nil && u.Uid != "0" {
			return u
		}
	}
	if uid := os.Getenv("PKEXEC_UID"); uid != "" && uid != "0" {
		if u, err := user.LookupId(uid); err == nil && u.Uid != "0" {
			return u
		}
	}
	return namedOwner(os.Getenv("MAKIMA_OWNER"))
}

// namedOwner resolves a uid or username to an account, refusing root and
// anything that is not an account at all.
func namedOwner(who string) *user.User {
	if who == "" || who == "root" || who == "0" {
		return nil
	}
	if u, err := user.LookupId(who); err == nil && u.Uid != "0" {
		return u
	}
	if u, err := user.Lookup(who); err == nil && u.Uid != "0" {
		return u
	}
	return nil
}

// accountOwner fills in the ids and home a *user.User carries as strings.
func accountOwner(u *user.User) *owner {
	if u == nil || u.HomeDir == "" {
		return nil
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil
	}
	return &owner{Name: u.Username, UID: uid, GID: gid, Home: u.HomeDir}
}

// firstHumanUID is where a machine's own accounts stop and its people start.
// Below it are the dozens of accounts the system creates for itself, none of
// which is anybody.
func firstHumanUID() int {
	if runtime.GOOS == "darwin" {
		return 500
	}
	return 1000
}

// soleAccount is the machine's only person, when it has exactly one.
//
// The last resort, and the one that answers the case this whole file exists
// for: a personal machine set up over SSH as root, where nothing in the
// environment says who it belongs to and nobody is logged in at the screen.
// Guessing is acceptable precisely because there is only one thing to guess —
// with two accounts this returns nothing and the operator is asked to say.
func soleAccount() *owner {
	list, err := sshd.SystemAccounts{}.List()
	if err != nil {
		return nil
	}
	return onlyPerson(list, firstHumanUID())
}

// onlyPerson picks the one account above first that is a person, or nothing
// when there are none or several.
func onlyPerson(list []*sshd.SessionUser, first int) *owner {
	var found *owner
	for _, u := range list {
		if u.UID == 0 || u.UID < first {
			continue
		}
		if found != nil {
			return nil
		}
		found = &owner{Name: u.Name, UID: u.UID, GID: u.GID, Home: u.Home}
	}
	return found
}

// owner is the account this node belongs to, or nil on a machine where nobody
// could be found.
//
// Resolved once, by learnOwner, and read from there afterwards. Working it out
// again on every status request would mean asking the machine's directory
// service about every account it has, several times a second, to re-derive an
// answer that cannot have changed.
func (n *node) owner() *owner {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ownerLocked()
}

// ownerLocked is owner with n.mu already held.
func (n *node) ownerLocked() *owner { return n.ownerAcct }

// learnOwner resolves the owner once at startup and writes it down, so that
// the next start does not depend on how this one happened to be launched.
//
// Saying where the answer came from is the point of the log line: "the only
// account on this machine" is a guess, and somebody reading the log on a
// machine where it guessed wrong should be able to see that it did.
func (n *node) learnOwner() {
	n.mu.Lock()
	stored := n.file.Owner
	o, why := ownerFor(stored)
	n.ownerAcct = o

	var err error
	changed := o != nil && o.Name != stored
	if changed {
		n.file.Owner = o.Name
		err = conf.Save(n.cfgPath, n.file)
	}
	n.mu.Unlock()

	switch {
	case o == nil:
		logf("owner: unknown — no desktop socket, and files from peers will land in /var/lib/makima/inbox")
		logf("owner: name the account this machine belongs to with:  sudo makima owner <user>")
	case changed:
		logf("owner: %s, from %s", o.Name, why)
		if err != nil {
			logf("owner: could not write it to the config, so the next start will work it out again: %v", err)
		}
	}
}

// SetOwner names the account this machine's makima belongs to.
//
// Takes effect at once rather than at the next start: the desktop socket is
// reopened for the new account and the inbox moves to their home, because
// somebody who has just run this to fix a machine they cannot read the status
// of should not then have to restart the daemon to find out whether it worked.
func (n *node) SetOwner(name string) error {
	u := namedOwner(name)
	if u == nil {
		if name == "root" || name == "0" {
			return errors.New("root cannot be the owner: the point of an owner is the socket a person can read, and root already has the one that can change things")
		}
		return fmt.Errorf("no local account %q", name)
	}
	o := accountOwner(u)
	if o == nil {
		return fmt.Errorf("%s has no home directory to put anything in", name)
	}

	n.mu.Lock()
	n.file.Owner = o.Name
	n.ownerAcct = o
	err := conf.Save(n.cfgPath, n.file)
	n.mu.Unlock()
	if err != nil {
		return err
	}

	n.openGUISocket(n.cfgPath)
	n.applyInbox()
	logf("owner: %s", o.Name)
	return nil
}
