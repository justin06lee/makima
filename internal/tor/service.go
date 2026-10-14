package tor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
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

	// extra are other onion services published beside Key's, forwarding to
	// the same target — the addresses fifteen-word invites lead to. Changed
	// by SetExtra, which kicks the running tor to catch up.
	mu    sync.Mutex
	extra []Key
	kick  chan struct{}
}

// SetExtra publishes these keys' onion services too, for as long as they are
// set, and takes down any that are no longer in the list.
func (s *Service) SetExtra(keys []Key) {
	s.mu.Lock()
	s.extra = slices.Clone(keys)
	kick := s.kickLocked()
	s.mu.Unlock()
	select {
	case kick <- struct{}{}:
	default:
	}
}

func (s *Service) extras() []Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.extra)
}

func (s *Service) kicked() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kickLocked()
}

func (s *Service) kickLocked() chan struct{} {
	if s.kick == nil {
		s.kick = make(chan struct{}, 1)
	}
	return s.kick
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

	published := map[string]bool{}
	s.syncExtras(t, published)

	// Reaching the service is checked alongside rather than before anything
	// else, so an invite minted in the meantime is published at once.
	reached := make(chan error, 1)
	go func() { reached <- s.reach(ctx, t, host) }()
	for {
		select {
		case err := <-reached:
			if err != nil {
				return false, err
			}
			healthy = true
			reached = nil
			s.note(ServiceState{Host: host, Phase: PhaseReachable})
			s.Logger.Printf("onion service: reachable from anywhere at %s", host)
		case <-s.kicked():
			s.syncExtras(t, published)
		case <-ctx.Done():
			return healthy, ctx.Err()
		case <-t.Done():
			return healthy, t.Err()
		}
	}
}

// syncExtras publishes the extra services not yet up and takes down the ones
// no longer wanted. published is what this tor has up, by address.
func (s *Service) syncExtras(t *Tor, published map[string]bool) {
	want := map[string]Key{}
	for _, k := range s.extras() {
		want[k.Host()] = k
	}
	for host := range published {
		if _, ok := want[host]; !ok {
			if err := t.Unpublish(host); err != nil {
				s.Logger.Printf("onion service: take down %s: %v", host, err)
			}
			delete(published, host)
		}
	}
	for host, k := range want {
		if published[host] {
			continue
		}
		if _, err := t.Publish(k, s.VirtPort, s.Target); err != nil {
			s.Logger.Printf("onion service: publish %s: %v", host, err)
			continue
		}
		published[host] = true
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
