package relay

import (
	"sync"
	"time"
)

// dialLimit is a token bucket per remote address.
//
// It sits in front of the handshake rather than behind it, because the
// handshake is the expensive half: a goroutine, a read buffer and a ten-second
// deadline, all spent before the far end has proved anything. One host opening
// connections as fast as it can should not be able to spend the relay's whole
// budget while it does.
type dialLimit struct {
	burst int
	every time.Duration
	max   int // hosts tracked at once; past it, new ones share overflow

	mu sync.Mutex
	at map[string]*dialBucket
}

type dialBucket struct {
	tokens float64
	last   time.Time
}

// idleTTL is how long an address is remembered after its last attempt. Long
// enough to cover a reconnect, short enough that a scanned relay does not
// accumulate a row per address it has ever seen.
const idleTTL = 10 * time.Minute

// maxTracked is how many hosts are remembered at once, and overflow the one
// budget every host past that shares. See allow.
const (
	maxTracked = 4096
	overflow   = "*"
)

func newDialLimit(burst int, every time.Duration) *dialLimit {
	return &dialLimit{burst: burst, every: every, max: maxTracked, at: map[string]*dialBucket{}}
}

// allow reports whether one attempt from host may proceed.
func (d *dialLimit) allow(host string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	b, ok := d.at[host]
	if !ok {
		// Swept on insert, so there is no timer to stop when the relay stops.
		for k, v := range d.at {
			if now.Sub(v.last) > idleTTL {
				delete(d.at, k)
			}
		}
		// A full table does not grow: a public relay is scanned from
		// everywhere, an IPv6 host has a /64 to walk, and behind a trusted
		// proxy that passes X-Forwarded-For through untouched every request
		// can name a new address. Past the limit new arrivals share one
		// budget, and the hosts already held keep theirs.
		if len(d.at) >= d.max {
			host = overflow
			b = d.at[host]
		}
		if b == nil {
			b = &dialBucket{tokens: float64(d.burst), last: now}
			d.at[host] = b
		}
	}

	b.tokens += now.Sub(b.last).Seconds() / d.every.Seconds()
	if b.tokens > float64(d.burst) {
		b.tokens = float64(d.burst)
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
