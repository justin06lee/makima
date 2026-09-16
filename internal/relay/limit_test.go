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
