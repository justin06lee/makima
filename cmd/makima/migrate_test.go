package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/migrate"
)

// The refusals: each has to come back before Tailscale is so much as looked
// at, which is what makes them safe to answer with "failed" and walk away.
func TestCutoverRefusesBeforeTouchingAnything(t *testing.T) {
	dir := t.TempDir()
	base := cutoverOpts{
		path:       filepath.Join(dir, "node.json"),
		name:       "tenet",
		controller: "mac",
		statePath:  filepath.Join(dir, "migrate.json"),
	}

	cases := map[string]func(o *cutoverOpts){
		"no invite":                   func(o *cutoverOpts) {},
		"not on the network it holds": func(o *cutoverOpts) { o.serverSelf = true },
		"a broken invite":             func(o *cutoverOpts) { o.input.Invite = "mk1_notreally" },
	}
	for name, change := range cases {
		o := base
		change(&o)
		st := runCutover(context.Background(), o)
		if st.State != migrate.StateFailed {
			t.Errorf("%s: state %q (%s), want failed", name, st.State, st.Detail)
		}
		if st.Step == "tailscale" || strings.Contains(st.Detail, "Tailscale back") {
			t.Errorf("%s: it got as far as Tailscale", name)
		}
		b, err := os.ReadFile(o.statePath)
		if err != nil {
			t.Fatalf("%s: no state written: %v", name, err)
		}
		if s, _ := migrate.ReadState(b); s.State != migrate.StateFailed {
			t.Errorf("%s: the file says %q", name, s.State)
		}
	}
}
