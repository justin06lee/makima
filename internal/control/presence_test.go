package control

import (
	"testing"
	"time"
)

// A node that stops polling has to be published as offline. Before, going
// offline changed nothing in the store, no netmap was sent, and every peer
// kept showing it online.
func TestGoingOfflineIsPublished(t *testing.T) {
	s := newStore(t)
	laptop := join(t, s, "laptop")
	join(t, s, "desktop")

	if s.notePresence() {
		t.Fatal("the first look reported a change")
	}
	before := s.Version()
	changed := s.Changed()

	s.mu.Lock()
	s.findByMachineKey(laptop.MachineKey).LastSeen = time.Now().Add(-10 * time.Minute)
	s.mu.Unlock()

	if !s.notePresence() {
		t.Fatal("a node gone quiet for ten minutes was not noticed")
	}
	if s.Version() <= before {
		t.Error("the netmap version did not move, so no poller would hear")
	}
	select {
	case <-changed:
	default:
		t.Error("waiting pollers were not woken")
	}
	if s.notePresence() {
		t.Error("the same state was published twice")
	}

	// And coming back is published too.
	s.mu.Lock()
	s.findByMachineKey(laptop.MachineKey).LastSeen = time.Now()
	s.mu.Unlock()
	if !s.notePresence() {
		t.Error("a node coming back was not published")
	}
}
