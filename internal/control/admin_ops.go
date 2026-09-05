package control

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/policy"
)

// The operations an administrator performs on a mesh, separated from the hot
// path in store.go so the file that serves netmaps stays about serving
// netmaps.

// AddRelay registers a relay and, if it is the first, makes it active for the
// whole mesh.
func (s *Store) AddRelay(url string, k key.Public) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range s.state.Relays {
		if r.URL == url {
			return fmt.Errorf("relay %s is already registered", url)
		}
	}
	s.state.Relays = append(s.state.Relays, netmap.Relay{URL: url, Key: k})
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// RemoveRelay drops a relay. Removing the active one promotes the next.
func (s *Store) RemoveRelay(url string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := make([]netmap.Relay, 0, len(s.state.Relays))
	found := false
	for _, r := range s.state.Relays {
		if r.URL == url {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return fmt.Errorf("no relay registered at %s", url)
	}

	s.state.Relays = kept
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// Relays lists registered relays in preference order.
func (s *Store) Relays() []netmap.Relay {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]netmap.Relay(nil), s.state.Relays...)
}

// PreferRelay moves a relay to the front, making it the mesh's active one.
//
// The whole mesh moves at once: the choice travels in the netmap, so every
// node switches on its next poll. Nodes cannot meet on different relays, so
// there is no partial state to be in.
func (s *Store) PreferRelay(url string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	for i, r := range s.state.Relays {
		if r.URL == url {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("no relay registered at %s", url)
	}
	if idx == 0 {
		return nil
	}

	chosen := s.state.Relays[idx]
	rest := append([]netmap.Relay{}, s.state.Relays[:idx]...)
	rest = append(rest, s.state.Relays[idx+1:]...)
	s.state.Relays = append([]netmap.Relay{chosen}, rest...)

	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// SetPolicy replaces the access-control policy.
//
// Validated before it is stored, so a typo in an ACL is an error message
// rather than an outage discovered by whoever can no longer reach the
// database.
func (s *Store) SetPolicy(p *policy.Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.Policy = p
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// Policy returns the mesh's policy, or the permissive default when none is
// set.
func (s *Store) Policy() *policy.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policyLocked()
}

// SetDNS turns mesh name resolution on or off and sets the suffix.
func (s *Store) SetDNS(enabled bool, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.DNSEnabled = enabled
	if domain != "" {
		s.state.Domain = domain
	}
	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// DNSSettings reports the mesh's name configuration.
func (s *Store) DNSSettings() (enabled bool, domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.DNSEnabled, s.domainLocked()
}

// ApproveRoutes accepts some or all of a node's advertised subnets.
//
// Approval is explicit and per-prefix because the consequence is not local: an
// approved route tells every node in the mesh to send that prefix into the
// tunnel. A node that advertises 0.0.0.0/0 is asking to become everyone's
// default gateway, and that must be a decision somebody makes rather than one
// a node can take for itself.
func (s *Store) ApproveRoutes(name string, routes []netip.Prefix, exit bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := s.findByName(name)
	if n == nil {
		return fmt.Errorf("no node named %q", name)
	}

	for _, r := range routes {
		if !advertised(n.AdvertisedRoutes, r) {
			return fmt.Errorf("%s has not advertised %s; it advertises %v", name, r, n.AdvertisedRoutes)
		}
		if !advertised(n.ApprovedRoutes, r) {
			n.ApprovedRoutes = append(n.ApprovedRoutes, r)
		}
	}

	if exit {
		if !n.AdvertisesExit {
			return fmt.Errorf("%s has not offered to be an exit node", name)
		}
		n.ExitApproved = true
		n.ExitRevoked = false
	}

	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// RevokeRoutes withdraws approval.
func (s *Store) RevokeRoutes(name string, routes []netip.Prefix, exit bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := s.findByName(name)
	if n == nil {
		return fmt.Errorf("no node named %q", name)
	}

	if len(routes) > 0 {
		kept := make([]netip.Prefix, 0, len(n.ApprovedRoutes))
		for _, existing := range n.ApprovedRoutes {
			if !advertised(routes, existing) {
				kept = append(kept, existing)
			}
		}
		n.ApprovedRoutes = kept
	}
	if exit {
		n.ExitApproved = false
		n.ExitRevoked = true
	}

	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// SetTags replaces a node's policy tags.
func (s *Store) SetTags(name string, tags []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := s.findByName(name)
	if n == nil {
		return fmt.Errorf("no node named %q", name)
	}
	n.Tags = tags

	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

// ExpireNode forces a node to re-authenticate.
//
// Distinct from Forget: the node record survives, keeping its address and its
// approved routes, but it must present a valid auth key again before it is
// served another netmap. That is the difference between "this machine is
// decommissioned" and "this machine may have been stolen".
func (s *Store) ExpireNode(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := s.findByName(name)
	if n == nil {
		return fmt.Errorf("no node named %q", name)
	}
	n.Expired = true
	// A key that can no longer be trusted must not keep its signature, or
	// re-admitting the machine would silently restore it.
	n.KeySignature = nil

	if err := s.save(); err != nil {
		return err
	}
	s.bump()
	return nil
}

func (s *Store) findByName(name string) *Node {
	for _, n := range s.state.Nodes {
		if n.Name == name {
			return n
		}
	}
	return nil
}

func advertised(list []netip.Prefix, want netip.Prefix) bool {
	for _, p := range list {
		if p == want {
			return true
		}
	}
	return false
}

// touch records that a node was heard from. Callers must hold the lock.
func (n *Node) touch(now time.Time) { n.LastSeen = now }
