//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// A second makimad waits for the first to exit instead of starting beside
// it. Started beside it, it failed to bind UDP 51820 and exited, and launchd
// restarted it every ten seconds — each start counting against a pending
// update, which three of them roll back.
func TestASecondDaemonWaitsForTheFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "makimad.lock")

	first, err := lockInstance(path, func(string) { t.Error("the first daemon waited") }, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	waited := make(chan string, 1)
	got := make(chan *os.File, 1)
	go func() {
		f, err := lockInstance(path, func(holder string) { waited <- holder }, time.Millisecond)
		if err != nil {
			t.Error(err)
		}
		got <- f
	}()

	select {
	case holder := <-waited:
		if holder != strconv.Itoa(os.Getpid()) {
			t.Errorf("told the holder is %q, want this process, %d", holder, os.Getpid())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second daemon did not notice the first")
	}
	select {
	case <-got:
		t.Fatal("the second daemon started while the first still ran")
	case <-time.After(50 * time.Millisecond):
	}

	// The first exits; its lock goes with it.
	first.Close()

	select {
	case f := <-got:
		if f == nil {
			t.Fatal("no lock")
		}
		defer f.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the second daemon never started after the first exited")
	}
}
