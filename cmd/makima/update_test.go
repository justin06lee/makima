package main

import (
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/netmap"
)

func TestHowAMachinesUpdateReads(t *testing.T) {
	w := &updateWatch{tag: "v0.3.0", started: time.Now()}
	failed := &netmap.UpdateStatus{Tag: "v0.3.0", State: netmap.UpdateFailed, Error: "no space left"}
	for _, tc := range []struct {
		name    string
		version string
		update  *netmap.UpdateStatus
		online  bool
		moving  bool
		want    string
		final   bool
	}{
		{"arrived", "v0.3.0", nil, true, false, "✓ v0.3.0", true},
		{"a build past it", "v0.3.0-4-gabc1234", nil, true, false, "left alone", true},
		{"newer", "v0.4.0", nil, true, false, "left alone", true},
		{"installing", "v0.2.0", &netmap.UpdateStatus{Tag: "v0.3.0", State: netmap.UpdateInstalling}, true, false, "installing", false},
		{"restarting", "v0.2.0", &netmap.UpdateStatus{Tag: "v0.3.0", State: netmap.UpdateRestarting}, true, false, "restarting", false},
		{"failed while watched", "v0.2.0", failed, true, true, "✗ no space left", true},
		// Left over from an earlier try: it is about to try again.
		{"an old failure, just asked", "v0.2.0", failed, true, false, "waiting", false},
		{"a failure about another release", "v0.2.0", &netmap.UpdateStatus{Tag: "v0.2.5", State: netmap.UpdateFailed}, true, false, "waiting", false},
		{"too old to be asked", "", nil, true, false, "make install", true},
		{"off", "v0.2.0", nil, false, false, "off", true},
		{"not started yet", "v0.2.0", nil, true, false, "waiting", false},
	} {
		d := &device{name: "tenet", moving: tc.moving}
		w.place(d, tc.version, tc.update, tc.online)
		if !strings.Contains(d.text, tc.want) || d.final != tc.final {
			t.Errorf("%s: %q final=%v, want %q final=%v", tc.name, d.text, d.final, tc.want, tc.final)
		}
	}
}
