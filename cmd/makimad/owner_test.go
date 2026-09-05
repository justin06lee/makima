package main

import (
	"os/user"
	"testing"
)

func TestInvokerReadsEveryWayOfSayingWho(t *testing.T) {
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
			for _, e := range []string{"SUDO_USER", "PKEXEC_UID", "MAKIMA_OWNER"} {
				t.Setenv(e, "")
			}
			t.Setenv(tc.env, tc.value)
			u := invoker()
			if u == nil || u.Uid != me.Uid {
				t.Errorf("invoker() = %v, want uid %s", u, me.Uid)
			}
		})
	}
}

func TestInvokerIgnoresRoot(t *testing.T) {
	for _, e := range []string{"SUDO_USER", "PKEXEC_UID", "MAKIMA_OWNER"} {
		t.Setenv(e, "")
	}
	t.Setenv("SUDO_USER", "root")
	t.Setenv("PKEXEC_UID", "0")
	// consoleUID may still find the logged-in user on a Mac, which is
	// correct; what must not happen is root being returned as a person.
	if u := invoker(); u != nil && u.Uid == "0" {
		t.Error("invoker() returned root")
	}
}
