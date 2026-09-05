package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinkIntoLinksTheBinaryAndLeavesRealFilesAlone(t *testing.T) {
	dir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Skip("no executable path")
	}

	// Something already installed by other means must never be replaced.
	real := filepath.Join(dir, "makimad")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	linked, err := linkInto(dir, self)
	if err != nil {
		t.Fatal(err)
	}
	if len(linked) != 1 || linked[0] != "makima" {
		t.Fatalf("linked %v, want [makima]", linked)
	}

	got, err := os.Readlink(filepath.Join(dir, "makima"))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(self)
	if got != want {
		t.Errorf("link points at %s, want %s", got, want)
	}

	if fi, err := os.Lstat(real); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Error("a real makimad in the link directory was replaced")
	}

	// Running it again is what `makima up` does every time; it must be quiet.
	again, err := linkInto(dir, self)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Errorf("second run linked %v, want nothing", again)
	}
}

func TestLinkIntoDoesNothingFromItsOwnDirectory(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "makima")
	if err := os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	linked, err := linkInto(dir, self)
	if err != nil {
		t.Fatal(err)
	}
	if len(linked) != 0 {
		t.Errorf("linked %v into its own directory", linked)
	}
}
