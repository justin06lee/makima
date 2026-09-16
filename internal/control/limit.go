package control

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// A sealed envelope stops anything unauthenticated getting past the first
// decryption — but reaching that decryption costs a goroutine, a descriptor
// and, for a map request, sixty seconds of holding both. That is spent before
// anybody has proved anything, so it is what needs bounding.
//
//	maxPolls    concurrent map requests. A long poll is cheap to make and
//	            expensive to hold, which is the shape of an exhaustion attack.
//	register*   how fast one address may attempt to register. Auth keys are not
//	            guessable, but an unbounded endpoint is still a free way to make
//	            the server write its state file.
const (
	maxPolls       = 512
	registerBurst  = 10
	registerEvery  = 6 * time.Second
	limiterIdleTTL = 10 * time.Minute
)

// polls bounds concurrent long polls.
type polls struct{ slots chan struct{} }

func newPolls(n int) *polls { return &polls{slots: make(chan struct{}, n)} }

// take claims a slot without waiting, reporting whether it got one.
func (p *polls) take() bool {
	select {
	case p.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p *polls) done() { <-p.slots }

// buckets rate-limits by client address with a token bucket each.
//
// Keyed by address rather than by machine key on purpose: the key is inside
// the envelope, and the point of this is to refuse the work before the
// envelope is opened.
type buckets struct {
	burst int
	every time.Duration

	mu sync.Mutex
	at map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newBuckets(burst int, every time.Duration) *buckets {
	return &buckets{burst: burst, every: every, at: map[string]*bucket{}}
}

// allow reports whether one attempt from addr may proceed.
func (b *buckets) allow(addr string, now time.Time) bool {
	key := hostOf(addr)

	b.mu.Lock()
	defer b.mu.Unlock()

	e, ok := b.at[key]
	if !ok {
		// Sweep on insert rather than on a timer: the map only grows when a
		// new address arrives, so that is the moment to drop the idle ones,
		// and there is no goroutine to stop when the server does.
		for k, v := range b.at {
			if now.Sub(v.last) > limiterIdleTTL {
				delete(b.at, k)
			}
		}
		e = &bucket{tokens: float64(b.burst), last: now}
		b.at[key] = e
	}

	e.tokens += now.Sub(e.last).Seconds() / b.every.Seconds()
	if e.tokens > float64(b.burst) {
		e.tokens = float64(b.burst)
	}
	e.last = now

	if e.tokens < 1 {
		return false
	}
	e.tokens--
	return true
}

// hostOf is the address without its port, so a client cannot get a fresh
// budget by opening a new connection.
func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// tooMany answers a request that was refused for load, with how long to wait.
func tooMany(w http.ResponseWriter, retryAfter time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	http.Error(w, "too many requests; try again shortly", http.StatusServiceUnavailable)
}
