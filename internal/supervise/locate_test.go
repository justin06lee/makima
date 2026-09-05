package supervise

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocatePrefersTheBinaryBesideTheExecutable(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("no executable path")
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}

	// The test binary's own directory is writable and on nobody's PATH, which
	// is exactly the situation the app's bundle is in.
	name := "makima-locate-test-helper"
	p := filepath.Join(filepath.Dir(self), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Skipf("cannot write beside the test binary: %v", err)
	}
	defer os.Remove(p)

	got, err := Locate(name)
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Errorf("Locate(%q) = %q, want %q", name, got, p)
	}
}

func TestLocateSaysWhenNothingIsThere(t *testing.T) {
	if _, err := Locate("makima-definitely-not-installed"); err == nil {
		t.Error("found a binary that does not exist")
	}
}
