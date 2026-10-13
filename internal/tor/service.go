package tor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Service keeps one onion service published for as long as its context
// lasts: it starts tor, waits for it to join the network, publishes, checks
// the service can actually be reached, and starts over if tor dies.
type Service struct {
	DataDir string
	Key     Key

	// VirtPort is the port the onion address answers on; Target is where tor
	// forwards those connections, a loopback host:port.
	VirtPort int
	Target   string

	Logger *log.Logger

	// OnState is told every change in how publishing is going.
	OnState func(ServiceState)
}

// Phases of publishing an onion service, in order.
const (
	PhaseOff          = "off"           // not publishing, on purpose
	PhaseNotInstalled = "not-installed" // no tor binary on this machine
	PhaseStarting     = "starting"      // starting tor
	PhaseConnecting   = "connecting"    // tor is joining the network
	PhasePublishing   = "publishing"    // published; waiting to be reachable
	PhaseReachable    = "reachable"     // reached through tor, from tor
	PhaseFailed       = "failed"        // something went wrong; retrying
)

// ServiceState is where publishing has got to.
type ServiceState struct {
	Host     string    `json:"host"`
	Phase    string    `json:"phase"`
	Progress int       `json:"progress,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Since    time.Time `json:"since,omitzero"`
}

// Retry delays. Tor that is missing is looked for again now and then, in case
// somebody installs it; tor that keeps dying is restarted less and less often.
const (
	notInstalledRetry = 5 * time.Minute
	minRestart        = 5 * time.Second
	maxRestart        = 5 * time.Minute
)

// reachTimeout is how long a freshly published service is given to become
// reachable. Publishing uploads descriptors to the network, and the first
// clients can fail to find them for a while.
const reachTimeout = 3 * time.Minute

// Run publishes until ctx ends.
func (s *Service) Run(ctx context.Context) {
	if s.Logger == nil {
		s.Logger = log.Default()
	}
	host := s.Key.Host()
	backoff := minRestart
	for ctx.Err() == nil {
		healthy, err := s.once(ctx, host)
		if ctx.Err() != nil {
			return
		}

		wait := backoff
		switch {
		case errors.Is(err, ErrNotInstalled):
			s.note(ServiceState{Host: host, Phase: PhaseNotInstalled, Detail: err.Error()})
			wait = notInstalledRetry
		default:
			s.note(ServiceState{Host: host, Phase: PhaseFailed, Detail: err.Error()})
			s.Logger.Printf("onion service: %v; trying again in %s", err, wait)
		}
		if healthy {
			backoff = minRestart
		} else {
			backoff = min(backoff*2, maxRestart)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// once runs one tor to the end. healthy is whether it got as far as being
// reachable, which resets the backoff.
func (s *Service) once(ctx context.Context, host string) (healthy bool, err error) {
	s.note(ServiceState{Host: host, Phase: PhaseStarting})
	t, err := Start(s.DataDir, s.Logger)
	if err != nil {
		return false, err
	}
	defer t.Close()

	if err := s.connect(ctx, t, host); err != nil {
		return false, err
	}

	if _, err := t.Publish(s.Key, s.VirtPort, s.Target); err != nil {
		return false, err
	}
	s.note(ServiceState{Host: host, Phase: PhasePublishing})

	if err := s.reach(ctx, t, host); err != nil {
		return false, err
	}
	s.note(ServiceState{Host: host, Phase: PhaseReachable})
	s.Logger.Printf("onion service: reachable from anywhere at %s", host)

	select {
	case <-ctx.Done():
		return true, ctx.Err()
	case <-t.Done():
		return true, t.Err()
	}
}

// connect waits for tor to join the network, reporting its progress.
func (s *Service) connect(ctx context.Context, t *Tor, host string) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last := -1
	for {
		p, summary, err := t.Bootstrap()
		if err != nil {
			return err
		}
		if p >= 100 {
			return nil
		}
		if p != last {
			s.note(ServiceState{Host: host, Phase: PhaseConnecting, Progress: p, Detail: summary})
			last = p
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.Done():
			return t.Err()
		case <-tick.C:
		}
	}
}

// reach connects to the service through tor itself — the same journey every
// node away from home makes — until it answers.
func (s *Service) reach(ctx context.Context, t *Tor, host string) error {
	ctx, cancel := context.WithTimeout(ctx, reachTimeout)
	defer cancel()
	addr := fmt.Sprintf("%s:%d", host, s.VirtPort)
	var last error
	for {
		attempt, stop := context.WithTimeout(ctx, time.Minute)
		conn, err := t.Dial(attempt, addr)
		stop()
		if err == nil {
			conn.Close()
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("published, but not reachable through tor: %v", last)
		case <-t.Done():
			return t.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (s *Service) note(st ServiceState) {
	st.Since = time.Now()
	if s.OnState != nil {
		s.OnState(st)
	}
}
