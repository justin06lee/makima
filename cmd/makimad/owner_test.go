package main

import (
	"os/user"
	"testing"

	"github.com/justin06lee/makima/internal/sshd"
)

// clearOwnerEnv removes every variable that could name an owner, so a test is
// measuring the source it means to.
func clearOwnerEnv(t *testing.T) {
	t.Helper()
	for _, e := range []string{"SUDO_USER", "PKEXEC_UID", "MAKIMA_OWNER"} {
		t.Setenv(e, "")
	}
}

func TestOwnerFromEveryWayOfSayingWho(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	if me.Uid == "0" {
		t.Skip("root has nobody behind it")
	}

	for _, tc := range []struct{ env, value string }{
		{"SUDO_USER", me.Username},
		{"PKEXEC_UID", me.Uid},
		{"MAKIMA_OWNER", me.Uid},
		{"MAKIMA_OWNER", me.Username},
	} {
		t.Run(tc.env+"="+tc.value, func(t *testing.T) {
			clearOwnerEnv(t)
			t.Setenv(tc.env, tc.value)

			o, why := ownerFor("")
			if o == nil || o.Name != me.Username {
				t.Fatalf("ownerFor() = %v, want %s", o, me.Username)
			}
			if why != "the environment" {
				t.Errorf("came from %q, want the environment", why)
			}
		})
	}
}

// The case this whole file exists for: nothing in the environment says who
// this machine is for, and the config does.
func TestOwnerFallsBackToTheConfig(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	if me.Uid == "0" {
		t.Skip("root is never an owner")
	}
	clearOwnerEnv(t)

	o, why := ownerFor(me.Username)
	if o == nil || o.Name != me.Username {
		t.Fatalf("ownerFor(%q) = %v, want that account", me.Username, o)
	}
	if why != "the configuration" {
		t.Errorf("came from %q, want the configuration", why)
	}
	if o.Home != me.HomeDir {
		t.Errorf("home = %q, want %q", o.Home, me.HomeDir)
	}
}

// The environment is the person running makima right now, so it outranks a
// name written down by an earlier start.
func TestOwnerPrefersTheEnvironmentToTheConfig(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Uid == "0" {
		t.Skip("needs a non-root current user")
	}
	clearOwnerEnv(t)
	t.Setenv("SUDO_USER", me.Username)

	o, why := ownerFor("nobody-by-this-name")
	if o == nil || o.Name != me.Username {
		t.Fatalf("ownerFor() = %v, want %s", o, me.Username)
	}
	if why != "the environment" {
		t.Errorf("came from %q, want the environment", why)
	}
}

func TestOwnerIsNeverRoot(t *testing.T) {
	clearOwnerEnv(t)
	t.Setenv("SUDO_USER", "root")
	t.Setenv("PKEXEC_UID", "0")

	// consoleUID may still find the logged-in user on a Mac, which is
	// correct; what must not happen is root being returned as a person.
	if o, _ := ownerFor("root"); o != nil && o.UID == 0 {
		t.Error("ownerFor() returned root")
	}
	if namedOwner("root") != nil || namedOwner("0") != nil {
		t.Error("namedOwner accepted root")
	}
}

func TestOnlyPersonIgnoresTheMachinesOwnAccounts(t *testing.T) {
	accounts := []*sshd.SessionUser{
		{Name: "root", UID: 0, Home: "/var/root"},
		{Name: "daemon", UID: 1, Home: "/"},
		{Name: "justin06lee", UID: 501, GID: 20, Home: "/Users/justin06lee"},
	}

	o := onlyPerson(accounts, 500)
	if o == nil || o.Name != "justin06lee" {
		t.Fatalf("onlyPerson() = %v, want justin06lee", o)
	}
	if o.UID != 501 || o.GID != 20 {
		t.Errorf("ids = %d:%d, want 501:20", o.UID, o.GID)
	}
}

// Two people is not a machine anybody can guess about, and guessing wrong
// would hand one person's mesh status to the other.
func TestOnlyPersonRefusesToChooseBetweenTwo(t *testing.T) {
	accounts := []*sshd.SessionUser{
		{Name: "alice", UID: 501, Home: "/Users/alice"},
		{Name: "bob", UID: 502, Home: "/Users/bob"},
	}
	if o := onlyPerson(accounts, 500); o != nil {
		t.Errorf("onlyPerson() = %v, want nothing on a machine with two people", o)
	}
	if o := onlyPerson(nil, 500); o != nil {
		t.Errorf("onlyPerson(nil) = %v, want nothing", o)
	}
}
