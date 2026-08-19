package netcfg

import (
	"net"
	"net/netip"
	"sort"
)

// LocalEndpoints lists the addresses this host believes it can be reached at,
// paired with the WireGuard listen port.
//
// This is the poor cousin of real discovery: it sees only what the host can
// see about itself, so it finds LAN addresses and genuinely public ones, and
// is blind to anything behind NAT. That is enough to make two machines on the
// same network connect directly, and nothing more — a node behind a router
// still needs the relay and the hole punching that come later.
//
// Filtering is by address rather than interface name deliberately. Matching on
// names means keeping a list of every VPN's naming convention (utun, wg, tun,
// tailscale) and being wrong about the next one; excluding the CGNAT range
// excludes every mesh address, including other makima and Tailscale
// interfaces, by construction.
func LocalEndpoints(port uint16) []netip.AddrPort {
	if port == 0 {
		return nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var out []netip.AddrPort
	seen := make(map[netip.AddrPort]bool)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()

			if !usableEndpoint(addr) {
				continue
			}
			ap := netip.AddrPortFrom(addr, port)
			if seen[ap] {
				continue
			}
			seen[ap] = true
			out = append(out, ap)
		}
	}

	// Stable order so an unchanged set of addresses does not look like a
	// change to the control server and bump the netmap version on every poll.
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// usableEndpoint reports whether an address is worth advertising to peers.
func usableEndpoint(addr netip.Addr) bool {
	switch {
	case !addr.IsValid():
		return false
	case addr.IsLoopback():
		return false
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return false
	case addr.IsMulticast(), addr.IsUnspecified():
		return false
	case CGNATRange.Contains(addr):
		// A mesh address, ours or another VPN's. Advertising it would tell
		// peers to reach us through a tunnel to reach a tunnel.
		return false
	case addr.Is6():
		// IPv6 endpoints are deferred until disco can rank paths properly;
		// advertising them now would have peers pick an untested path with no
		// way to fall back.
		return false
	}
	return true
}
