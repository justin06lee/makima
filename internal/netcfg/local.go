package netcfg

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

// LocalEndpoints lists the addresses this host believes it can be reached at,
// paired with the WireGuard listen port.
//
// It sees only what the host can see about itself: LAN addresses and genuinely
// public ones, blind to anything behind NAT. Enough for two machines on the
// same network; a node behind a router still needs the relay.
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

	var out []netip.AddrPort
	seen := make(map[netip.AddrPort]bool)
	hostAddrs(func(addr netip.Addr, _ net.Flags) {
		if !usableEndpoint(addr) {
			return
		}
		ap := netip.AddrPortFrom(addr, port)
		if !seen[ap] {
			seen[ap] = true
			out = append(out, ap)
		}
	})

	// Stable order so an unchanged set of addresses does not look like a
	// change to the control server and bump the netmap version on every poll.
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// NetworkAddrs lists the addresses that say which networks this host is on:
// every address LocalEndpoints would advertise, and its global IPv6 ones too,
// which are not advertised yet but tell one network from another where two
// hand out the same IPv4 address. Sorted.
//
// Not the addresses a VPN hands out. Those come and go when the VPN does,
// and the machine has not moved: treating Tailscale starting as a network
// move dropped every path makima had found, for nothing. So neither IPv6
// unique-local addresses (Tailscale's fd7a:115c:a1e0::/48 among them — Go
// counts them as global unicast) nor private addresses on a point-to-point
// interface, which is what every VPN's tunnel is, say where this machine is.
// A public address on one does: that is a PPP link carrying the machine's
// own connection.
func NetworkAddrs() []netip.Addr {
	var out []netip.Addr
	hostAddrs(func(addr netip.Addr, flags net.Flags) {
		if saysWhereWeAre(addr, flags) {
			out = append(out, addr)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// saysWhereWeAre is NetworkAddrs' test for one address on an interface with
// the given flags.
func saysWhereWeAre(addr netip.Addr, flags net.Flags) bool {
	if !usableEndpoint(addr) && !(addr.Is6() && addr.IsGlobalUnicast() && !IsMeshAddr(addr)) {
		return false
	}
	if ula.Contains(addr) {
		return false
	}
	if flags&net.FlagPointToPoint != 0 && (addr.IsPrivate() || IsMeshAddr(addr)) {
		return false
	}
	return true
}

// ula is IPv6's private range, fc00::/7.
var ula = netip.MustParsePrefix("fc00::/7")

// hostAddrs calls fn with every address on an interface that is up, is not
// loopback, and leads somewhere other than this host, and the interface's
// flags.
func hostAddrs(fn func(netip.Addr, net.Flags)) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || hostOnly(iface.Name) {
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
			if addr, ok := netip.AddrFromSlice(ipnet.IP); ok {
				fn(addr.Unmap(), iface.Flags)
			}
		}
	}
}

// hostOnly reports whether an interface is a bridge to containers or virtual
// machines on this host.
//
// These are matched by name, unlike VPNs, because nothing about the address
// gives them away: Docker's 172.17.0.1 and libvirt's 192.168.122.1 are
// ordinary private addresses. But they lead only into this host — and every
// other host running the same software has the very same address, so a peer
// told to try 172.17.0.1 reaches its own Docker bridge, not this machine. They
// also come and go as containers start, which is not this machine changing
// networks.
func hostOnly(name string) bool {
	for _, prefix := range []string{
		"docker", "br-", "veth", "virbr", "vnet", "lxcbr", "lxdbr", "incusbr",
		"cni", "flannel", "cali", "cilium", "weave", "podman", "vmnet", "vboxnet",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
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
	case IsMeshAddr(addr):
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
