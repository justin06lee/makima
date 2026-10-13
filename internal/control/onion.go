package control

import (
	"net/url"
	"slices"
	"strings"

	"github.com/justin06lee/makima/internal/tor"
)

// The onion service this server is published as: how every node reaches it
// from anywhere, with no port forward and no public address. The address is
// derived from a key kept beside the state (see makima-server serve), and tor
// does the publishing; the store's part is telling every node the address and
// remembering how publishing is going.

// OnionURL is the address nodes are told to reach a server at by its onion
// address. Port 80, which is the port the service answers on whatever port
// the server listens on.
func OnionURL(host string) string { return "http://" + host }

// isOnionURL reports whether a control URL is an onion address.
func isOnionURL(u string) bool {
	p, err := url.Parse(u)
	return err == nil && tor.IsOnion(p.Hostname())
}

// SetOnion makes host one of the addresses every node is told about, in place
// of any onion address this server had before — a server that lost its key
// file has a new address, and the old one leads nowhere.
func (s *Store) SetOnion(host string) error {
	u := OnionURL(strings.ToLower(host))

	s.mu.Lock()
	defer s.mu.Unlock()
	urls := slices.DeleteFunc(slices.Clone(s.state.ControlURLs), func(have string) bool {
		return isOnionURL(have) && have != u
	})
	if !slices.Contains(urls, u) {
		urls = append(urls, u)
	}
	if slices.Equal(urls, s.state.ControlURLs) {
		return nil
	}
	s.state.ControlURLs = urls
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// ClearOnion stops telling nodes about any onion address: a server running
// without tor would only send them knocking where nobody answers.
func (s *Store) ClearOnion() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	urls := slices.DeleteFunc(slices.Clone(s.state.ControlURLs), isOnionURL)
	if len(urls) == len(s.state.ControlURLs) {
		return nil
	}
	s.state.ControlURLs = urls
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// Onion is the onion URL nodes are told about, or "" when there is none.
func (s *Store) Onion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.state.ControlURLs {
		if isOnionURL(u) {
			return u
		}
	}
	return ""
}

// NoteTor records how publishing the onion service is going.
func (s *Store) NoteTor(st tor.ServiceState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.torState = st
}

// TorState is how publishing the onion service is going: the zero value for
// a server that is not publishing one.
func (s *Store) TorState() tor.ServiceState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.torState
}
