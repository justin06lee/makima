package tor

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

// Dialer reaches onion addresses, starting tor the first time it is needed
// and again whenever it has died.
//
// Starting tor is the slow part — seconds with a warm data directory, longer
// on a machine that has never run it — so a node that knows it will need it
// calls Warm, and the first dial away from home finds it already connected.
type Dialer struct {
	// DataDir is where tor keeps its state between runs; a warm one is what
	// makes the next start quick.
	DataDir string
	Logger  *log.Logger

	mu       sync.Mutex
	tor      *Tor
	starting chan struct{} // non-nil while a start is under way
	lastErr  error
	failedAt time.Time
}

// ConnectTimeout bounds tor joining the network plus one onion connection,
// when the caller has set no tighter deadline of its own. Onion circuits are
// built on demand and a cold start downloads the network's consensus; a
// minute and a half covers both on a poor connection.
const ConnectTimeout = 90 * time.Second

// retryAfter is how long a failed start is remembered, so a node polling
// every few seconds does not spawn tor every few seconds while it is missing.
const retryAfter = 30 * time.Second

// Warm starts tor in the background, if it is not running already.
func (d *Dialer) Warm() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), ConnectTimeout)
		defer cancel()
		if t, err := d.get(ctx); err == nil {
			_ = t.WaitReady(ctx)
		}
	}()
}

// DialContext connects to an onion address through tor. The shape matches
// what bypass.Binder hands its onion route.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !IsOnion(address) {
		return nil, errNotOnion
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ConnectTimeout)
		defer cancel()
	}
	t, err := d.get(ctx)
	if err != nil {
		return nil, err
	}
	if err := t.WaitReady(ctx); err != nil {
		return nil, err
	}
	return t.Dial(ctx, address)
}

// get returns the running tor, starting one if there is none.
func (d *Dialer) get(ctx context.Context) (*Tor, error) {
	for {
		d.mu.Lock()
		if d.tor != nil && d.tor.Err() == nil {
			t := d.tor
			d.mu.Unlock()
			return t, nil
		}
		if d.starting != nil {
			wait := d.starting
			d.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if d.lastErr != nil && time.Since(d.failedAt) < retryAfter {
			err := d.lastErr
			d.mu.Unlock()
			return nil, err
		}
		if d.tor != nil {
			d.logger().Printf("tor: %v; starting it again", d.tor.Err())
			d.tor = nil
		}
		d.starting = make(chan struct{})
		d.mu.Unlock()

		t, err := Start(d.DataDir, d.logger())

		d.mu.Lock()
		close(d.starting)
		d.starting = nil
		if err != nil {
			d.lastErr, d.failedAt = err, time.Now()
			d.mu.Unlock()
			return nil, err
		}
		d.tor, d.lastErr = t, nil
		d.mu.Unlock()
		return t, nil
	}
}

func (d *Dialer) logger() *log.Logger {
	if d.Logger == nil {
		return log.Default()
	}
	return d.Logger
}

// Status is how the dialer's tor is doing, for a status page.
type Status struct {
	// Running is a tor process up; Progress is how far it has got joining
	// the network, 100 being connected.
	Running  bool   `json:"running"`
	Progress int    `json:"progress"`
	Summary  string `json:"summary,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Status reports on tor without starting it.
func (d *Dialer) Status() Status {
	d.mu.Lock()
	t, lastErr := d.tor, d.lastErr
	d.mu.Unlock()

	var st Status
	if lastErr != nil {
		st.Error = lastErr.Error()
	}
	if t == nil {
		return st
	}
	p, summary, err := t.Bootstrap()
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Running, st.Progress, st.Summary = true, p, summary
	return st
}

// Close stops tor, if it is running.
func (d *Dialer) Close() {
	d.mu.Lock()
	t := d.tor
	d.tor = nil
	d.mu.Unlock()
	if t != nil {
		t.Close()
	}
}
