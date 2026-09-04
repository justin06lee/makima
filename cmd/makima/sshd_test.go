package main

import (
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/localapi"
)

// When it is off, the useful output is how to switch it on.
func TestSSHStatusOffExplainsHowToStart(t *testing.T) {
	got := sshStatusReport(localapi.Status{})
	if !strings.Contains(got, "off") {
		t.Errorf("an inactive server did not say so: %q", got)
	}
	for _, want := range []string{"makima sshd -on", "github:"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not mention %q:\n%s", want, got)
		}
	}
}

// The fingerprint has to be printed, because a host key that is only ever
// trusted on first use is not a check at all.
func TestSSHStatusOnShowsTheFingerprint(t *testing.T) {
	got := sshStatusReport(localapi.Status{
		Node: localapi.NodeInfo{Name: "desktop"},
		SSH: localapi.SSHInfo{
			Active:      true,
			Addr:        "100.64.0.2:2222",
			User:        "alex",
			Keys:        2,
			Sources:     []string{"github:justin06lee"},
			Fingerprint: "SHA256:abc123",
		},
	})

	for _, want := range []string{"100.64.0.2:2222", "alex", "2 authorized key", "github:justin06lee", "SHA256:abc123", "makima ssh desktop"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not mention %q:\n%s", want, got)
		}
	}
}

// A key source that failed to read is worth saying even when the server is up
// on an older set — otherwise a revoked key looks like it was revoked.
func TestSSHStatusSurfacesAKeyError(t *testing.T) {
	got := sshStatusReport(localapi.Status{SSH: localapi.SSHInfo{
		Active:   true,
		Addr:     "100.64.0.2:2222",
		Keys:     1,
		KeyError: "github: dial tcp: no route to host",
	}})
	if !strings.Contains(got, "no route to host") {
		t.Errorf("a stale key set gave no warning:\n%s", got)
	}
}
