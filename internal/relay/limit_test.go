package relay

import (
	"testing"
	"time"
)

func TestDialLimitRefusesABurst(t *testing.T) {
	d := newDialLimit(3, time.Second)
	now := time.Now()

	for i := range 3 {
		if !d.allow("10.0.0.1", now) {
			t.Fatalf("attempt %d within the burst was refused", i+1)
		}
	}
	if d.allow("10.0.0.1", now) {
		t.Error("a fourth attempt past the burst was allowed")
	}
	if !d.allow("10.0.0.2", now) {
		t.Error("a different address was refused because of the first one")
	}
	if !d.allow("10.0.0.1", now.Add(2*time.Second)) {
		t.Error("the bucket did not refill")
	}
}

func TestDialLimitForgetsIdleAddresses(t *testing.T) {
	d := newDialLimit(1, time.Second)
	start := time.Now()

	d.allow("10.0.0.1", start)
	d.allow("10.0.0.2", start)
	d.allow("10.0.0.3", start.Add(idleTTL+time.Minute))

	d.mu.Lock()
	n := len(d.at)
	d.mu.Unlock()
	if n != 1 {
		t.Errorf("the table holds %d addresses after a sweep, want 1", n)
	}
}

// A public relay is scanned from everywhere, and every host used to be a row
// for ten minutes however many arrived. A full table now puts new hosts on one
// shared budget, and the hosts it already holds keep theirs.
func TestDialLimitDoesNotGrowPastItsSize(t *testing.T) {
	d := newDialLimit(2, time.Minute)
	d.max = 2
	now := time.Now()

	d.allow("10.0.0.1", now)
	d.allow("10.0.0.2", now)

	// Past the limit, new arrivals spend one shared budget of two.
	if !d.allow("198.51.100.1", now) || !d.allow("198.51.100.2", now) {
		t.Fatal("arrivals past a full table were refused before the shared budget ran out")
	}
	if d.allow("198.51.100.3", now) {
		t.Error("a new host got a budget of its own past a full table")
	}
	d.mu.Lock()
	n := len(d.at)
	d.mu.Unlock()
	if n > d.max+1 {
		t.Errorf("the table grew to %d rows past a limit of %d", n, d.max)
	}

	// The host already held still has the token it did not spend.
	if !d.allow("10.0.0.1", now) {
		t.Error("a host the table already held lost its budget to the newcomers")
	}
}
