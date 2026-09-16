package control

import (
	"testing"
	"time"
)

func TestPollsAreCapped(t *testing.T) {
	p := newPolls(2)
	if !p.take() || !p.take() {
		t.Fatal("the first two polls were refused")
	}
	if p.take() {
		t.Error("a third poll was admitted past a cap of two")
	}
	p.done()
	if !p.take() {
		t.Error("a slot freed by a finished poll was not reused")
	}
}

func TestRegistersAreRateLimited(t *testing.T) {
	b := newBuckets(3, time.Second)
	now := time.Now()

	for i := range 3 {
		if !b.allow("10.0.0.1:1234", now) {
			t.Fatalf("attempt %d within the burst was refused", i+1)
		}
	}
	if b.allow("10.0.0.1:1234", now) {
		t.Error("a fourth attempt past the burst was allowed")
	}

	// Another address has its own budget.
	if !b.allow("10.0.0.2:1234", now) {
		t.Error("a different address was refused because of the first one")
	}

	// And the budget refills with time.
	if !b.allow("10.0.0.1:1234", now.Add(2*time.Second)) {
		t.Error("the bucket did not refill")
	}
}

// A new port is not a new client: the budget follows the address.
func TestANewPortDoesNotGetAFreshBudget(t *testing.T) {
	b := newBuckets(1, time.Minute)
	now := time.Now()

	if !b.allow("10.0.0.1:1111", now) {
		t.Fatal("the first attempt was refused")
	}
	if b.allow("10.0.0.1:2222", now) {
		t.Error("reconnecting from a new port got a fresh budget")
	}
}

// The table must not grow without bound for a server that is scanned.
func TestIdleAddressesAreForgotten(t *testing.T) {
	b := newBuckets(1, time.Second)
	start := time.Now()

	b.allow("10.0.0.1:1", start)
	b.allow("10.0.0.2:1", start)

	// A later arrival sweeps whatever has gone quiet.
	b.allow("10.0.0.3:1", start.Add(limiterIdleTTL+time.Minute))

	b.mu.Lock()
	n := len(b.at)
	b.mu.Unlock()
	if n != 1 {
		t.Errorf("the table holds %d addresses after a sweep, want 1", n)
	}
}

func TestHostOfDropsThePort(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1:4242":  "10.0.0.1",
		"[fd00::1]:4242": "fd00::1",
		"10.0.0.1":       "10.0.0.1",
		"":               "",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
