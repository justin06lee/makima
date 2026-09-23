package control

import (
	"context"
	"log"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/justin06lee/makima/internal/ddns"
)

// DDNS is a DuckDNS name this server keeps pointed at its own public address.
//
// It is what makes the control plane findable from outside the network it
// lives on. The name goes into ControlURLs, so every node learns it and falls
// back to it; the server keeps it current, so it still leads here after the
// home connection's address changes.
type DDNS struct {
	Name  string `json:"name"`
	Token string `json:"token"`

	// Port is the port the router forwards to this server, which is almost
	// always the one it listens on.
	Port int `json:"port,omitempty"`
}

// URL is the address nodes are told to reach this server at by name.
func (d *DDNS) URL() string {
	host := ddns.Host(d.Name)
	if d.Port == 0 || d.Port == 80 {
		return "http://" + host
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(d.Port))
}

// DDNSStatus is how keeping the name current is going. It never carries the
// token.
type DDNSStatus struct {
	Name    string    `json:"name,omitempty"`
	URL     string    `json:"url,omitempty"`
	IP      string    `json:"ip,omitempty"`
	Updated time.Time `json:"updated,omitzero"`
	Error   string    `json:"error,omitempty"`
}

// SetDDNS starts keeping a DuckDNS name pointed here, and tells every node
// about it.
func (s *Store) SetDDNS(d DDNS) (string, error) {
	name, err := ddns.Name(d.Name)
	if err != nil {
		return "", err
	}
	d.Name = name

	s.mu.Lock()
	defer s.mu.Unlock()

	if old := s.state.DDNS; old != nil {
		s.state.ControlURLs = slices.DeleteFunc(s.state.ControlURLs, func(u string) bool { return u == old.URL() })
	}
	s.state.DDNS = &d
	if !slices.Contains(s.state.ControlURLs, d.URL()) {
		s.state.ControlURLs = append(s.state.ControlURLs, d.URL())
	}
	if err := s.save(); err != nil {
		return "", err
	}
	s.ddnsStatus = DDNSStatus{}
	s.bump()

	// Refresh now rather than at the next tick, so the name is right by the
	// time anybody tries it.
	select {
	case s.ddnsKick <- struct{}{}:
	default:
	}
	return d.URL(), nil
}

// ClearDDNS stops keeping the name current and stops telling nodes about it.
func (s *Store) ClearDDNS() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.state.DDNS
	if old == nil {
		return nil
	}
	s.state.ControlURLs = slices.DeleteFunc(s.state.ControlURLs, func(u string) bool { return u == old.URL() })
	s.state.DDNS = nil
	s.ddnsStatus = DDNSStatus{}
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// DDNSConfig is the configured name, or nil.
func (s *Store) DDNSConfig() *DDNS {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.DDNS == nil {
		return nil
	}
	d := *s.state.DDNS
	return &d
}

// DDNSState reports the name and how the last refresh went.
func (s *Store) DDNSState() DDNSStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.ddnsStatus
	if d := s.state.DDNS; d != nil {
		st.Name = ddns.Host(d.Name)
		st.URL = d.URL()
	}
	return st
}

func (s *Store) noteDDNS(r ddns.Result, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.ddnsStatus.Error = err.Error()
		return
	}
	s.ddnsStatus = DDNSStatus{IP: r.IP, Updated: time.Now()}
}

// RunDDNS keeps the configured name current until ctx ends: at once, every
// ddns.Every after, and whenever the name is changed.
//
// Quiet while nothing changes. It logs when the address moves — the event this
// exists for, and the one somebody would want to find in the log afterwards —
// and when refreshing starts or stops failing, not on every attempt.
func RunDDNS(ctx context.Context, store *Store, logger *log.Logger) {
	t := time.NewTicker(ddns.Every)
	defer t.Stop()

	for {
		if d := store.DDNSConfig(); d != nil {
			prev := store.DDNSState()
			r, err := ddns.Update(ctx, d.Name, d.Token)
			if ctx.Err() != nil {
				return
			}
			store.noteDDNS(r, err)

			host := ddns.Host(d.Name)
			switch {
			case err != nil && err.Error() != prev.Error:
				logger.Printf("ddns: could not update %s: %v", host, err)
			case err == nil && (r.IP != prev.IP || prev.Error != ""):
				logger.Printf("ddns: %s points at %s", host, r.IP)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-store.ddnsKick:
		}
	}
}
