package control

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/justin06lee/makima/internal/hostaddr"
)

// The server's own addresses: where a node on the same network reaches it
// directly, found on the machine itself rather than typed in. Named to every
// node ahead of the onion address, so that a node at home never goes through
// tor to reach a machine in the same room, and so that a node whose saved
// address went stale — the server's DHCP lease moved — is told the new one.
//
// Found again on every start and whenever the machine's addresses change, and
// never saved: they are the machine's, not the network's, and a saved one is
// exactly the stale address this is here to replace.

// localCheckInterval is how often the server looks at its own addresses.
const localCheckInterval = 5 * time.Second

// LocalURLs are the addresses a server listening at listen is reached at
// directly, given the addresses its machine holds on its networks.
//
// Every one of them for a server listening on all of its addresses, which is
// what makima-server serve does unless told otherwise; only the one it was
// told to listen on, if that is one; and none behind a reverse proxy on
// loopback, where nobody else can reach it directly at all.
func LocalURLs(listen net.Addr, held []netip.Addr) []string {
	tcp, ok := listen.(*net.TCPAddr)
	if !ok {
		return nil
	}
	ap := tcp.AddrPort()
	ip := ap.Addr().Unmap()
	port := strconv.Itoa(int(ap.Port()))

	var out []string
	add := func(a netip.Addr) {
		u := "http://" + net.JoinHostPort(a.String(), port)
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	switch {
	case ip.IsLoopback():
		return nil
	case ip.IsUnspecified():
		sorted := slices.Clone(held)
		slices.SortFunc(sorted, func(a, b netip.Addr) int { return a.Compare(b) })
		for _, a := range sorted {
			// 0.0.0.0 is IPv4 only; :: is both.
			if ip.Is4() && !a.Unmap().Is4() {
				continue
			}
			add(a.Unmap())
		}
	default:
		add(ip)
	}
	return out
}

// AdvertiseLocal keeps the addresses nodes are told about current with the
// machine's own, until ctx ends.
func AdvertiseLocal(ctx context.Context, s *Store, listen net.Addr) {
	t := time.NewTicker(localCheckInterval)
	defer t.Stop()
	for {
		s.SetLocalURLs(LocalURLs(listen, heldAddrs()))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// heldAddrs are the addresses this machine holds that another machine could
// reach it at: what it tells peers for WireGuard, by the same rules.
func heldAddrs() []netip.Addr {
	var out []netip.Addr
	for _, ap := range hostaddr.LocalEndpoints(1) {
		out = append(out, ap.Addr())
	}
	return out
}

// SetLocalURLs records the server's own addresses, and wakes every node when
// they changed.
func (s *Store) SetLocalURLs(urls []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Equal(urls, s.local) {
		return
	}
	s.local = slices.Clone(urls)
	s.bump()
}

// advertisedURLsLocked are the addresses every node is told: the server's
// own first, then the ones its operator added and its onion address.
func (s *Store) advertisedURLsLocked() []string {
	out := slices.Clone(s.local)
	for _, u := range s.state.ControlURLs {
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

// AdvertisedURLs are the addresses every node is told about.
func (s *Store) AdvertisedURLs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.advertisedURLsLocked()
}
