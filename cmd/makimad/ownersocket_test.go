package main

import (
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netmap"
)

// testNode is the least of a node that owning a machine needs: a config on
// disk and somewhere to put a socket.
//
// Under /tmp rather than t.TempDir(), which on macOS is already most of the
// hundred-odd bytes a Unix socket path may be.
func testNode(t *testing.T) *node {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "mak")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	nodeKey, machineKey, discoKey, err := conf.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := &conf.File{
		NodeKey:    nodeKey,
		MachineKey: machineKey,
		DiscoKey:   discoKey,
		Self: netmap.Node{
			Name:      "laptop",
			Key:       nodeKey.Public(),
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")},
		},
	}

	path := filepath.Join(dir, "node.json")
	if err := conf.Save(path, f); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return &node{cfgPath: path, file: f}
}

// The whole point, end to end: naming an owner opens the read-only socket that
// account can read, without a restart.
func TestSetOwnerOpensTheSocketAtOnce(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	if me.Uid == "0" {
		t.Skip("root cannot be an owner, and chowning to anybody else needs a second account")
	}

	n := testNode(t)
	if err := n.SetOwner(me.Username); err != nil {
		t.Fatalf("SetOwner: %v", err)
	}
	t.Cleanup(n.closeGUISocket)

	c, err := localapi.Dial(localapi.GUISocketPath(n.cfgPath))
	if err != nil {
		t.Fatalf("the socket a person reads was not opened: %v", err)
	}
	if _, err := c.Status(); err != nil {
		t.Errorf("status over the desktop socket: %v", err)
	}

	// And it is written down, so the next start does not have to work it out
	// from an environment that will not be there.
	f, err := conf.Load(n.cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if f.Owner != me.Username {
		t.Errorf("config owner = %q, want %q", f.Owner, me.Username)
	}
}

// Setting it again is how somebody hands the machine over, so the second call
// must not trip over the socket the first one left listening.
func TestSetOwnerTwiceReopensTheSocket(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Uid == "0" {
		t.Skip("needs a non-root current user")
	}

	n := testNode(t)
	if err := n.SetOwner(me.Username); err != nil {
		t.Fatalf("first SetOwner: %v", err)
	}
	if err := n.SetOwner(me.Username); err != nil {
		t.Fatalf("second SetOwner: %v", err)
	}
	t.Cleanup(n.closeGUISocket)

	if _, err := localapi.Dial(localapi.GUISocketPath(n.cfgPath)); err != nil {
		t.Fatalf("socket gone after being reopened: %v", err)
	}
}

func TestSetOwnerRefusesRootAndStrangers(t *testing.T) {
	n := testNode(t)

	if err := n.SetOwner("root"); err == nil {
		t.Error("SetOwner(root) was accepted")
	}
	if err := n.SetOwner("no-such-account-here"); err == nil {
		t.Error("SetOwner accepted an account that does not exist")
	}
	f, err := conf.Load(n.cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if f.Owner != "" {
		t.Errorf("config owner = %q after two refusals, want it untouched", f.Owner)
	}
}

// The bug this file is about: a daemon started with nothing at all to say
// whose machine it is — no sudo, no polkit, no config — must still end up with
// an owner and a socket that account can read, rather than silently opening
// nothing and looking to every non-root tool like a makima that is not there.
func TestADaemonNobodyNamedAnOwnerForStillOpensTheSocket(t *testing.T) {
	clearOwnerEnv(t)

	n := testNode(t)
	n.learnOwner()

	o := n.owner()
	if o == nil {
		t.Skip("this machine has nobody to be its owner: no console session and not exactly one account")
	}
	if o.UID == 0 {
		t.Fatalf("owner is root (%v)", o)
	}

	n.openGUISocket(n.cfgPath)
	t.Cleanup(n.closeGUISocket)

	if _, err := localapi.Dial(localapi.GUISocketPath(n.cfgPath)); err != nil {
		t.Fatalf("no socket for %s to read: %v", o.Name, err)
	}
}

// A daemon started by launchd at boot has no sudo behind it. What makes that
// work is this: the first start that *does* know writes the answer down.
func TestLearnOwnerWritesItDown(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Uid == "0" {
		t.Skip("needs a non-root current user")
	}
	clearOwnerEnv(t)
	t.Setenv("SUDO_USER", me.Username)

	n := testNode(t)
	n.learnOwner()

	if n.owner() == nil || n.owner().Name != me.Username {
		t.Fatalf("owner = %v, want %s", n.owner(), me.Username)
	}
	f, err := conf.Load(n.cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if f.Owner != me.Username {
		t.Errorf("config owner = %q, want %q", f.Owner, me.Username)
	}
}
