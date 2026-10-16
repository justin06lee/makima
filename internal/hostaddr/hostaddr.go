// Package hostaddr knows makima's address ranges, and which of this host's
// own addresses are worth telling peers about.
//
// It only reads — it lists the interfaces and never changes one — which is
// why it is not part of netcfg, the package that installs routes, firewall
// rules and resolvers. Anything that must not be able to reach those, the
// rootless mode above all, can use it without being one call away from them.
package hostaddr

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

// MeshRange is the address space makima hands out.
//
// Its own, and not Tailscale's 100.64.0.0/10, so the two can run on one
// machine at once. Sharing Tailscale's range meant they could not: on Linux
// Tailscale drops every packet from 100.64.0.0/10 that did not arrive on its
// own interface, so makima only worked with Tailscale stopped — and moving off
// Tailscale had to be a switch-over instead of something added beside it.
//
// A /16 in the middle of 10/8, away from the ranges that are taken by
// default: 10.0–10.1 by home routers and cloud VPCs, 10.42–10.43 by k3s,
// 10.96 by Kubernetes services, 10.128 and up by cloud regions, 10.211 by
// Parallels. Only /32 host routes are installed, so even a LAN that happens
// to use it loses only the few addresses peers actually hold.
var MeshRange = netip.MustParsePrefix("10.77.0.0/16")

// LegacyMeshRange is where makima allocated before it had a range of its own.
// Networks started then keep their addresses and keep working; they just
// cannot share a Linux machine with a running Tailscale.
var LegacyMeshRange = netip.MustParsePrefix("100.64.0.0/10")

// IsMeshAddr reports whether an address is one makima hands out, now or
// before. 100.64.0.0/10 is also Tailscale's, so it counts as somebody's
// tunnel either way.
func IsMeshAddr(a netip.Addr) bool {
	a = a.Unmap()
	return MeshRange.Contains(a) || LegacyMeshRange.Contains(a)
}

// MeshRangeOf is the range a mesh address came from.
func MeshRangeOf(a netip.Addr) (netip.Prefix, bool) {
	a = a.Unmap()
	switch {
	case MeshRange.Contains(a):
		return MeshRange, true
	case LegacyMeshRange.Contains(a):
		return LegacyMeshRange, true
	}
	return netip.Prefix{}, false
}

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
	hostAddrs(func(a ifAddr) {
		addr := a.prefix.Addr()
		if !usableEndpoint(addr) || (addr.Is6() && v6Unusable(a.iface, addr)) {
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

// Endpoints is what a node advertises: its own addresses, local, and what
// it was observed at or mapped to, observed — IPv4 first, its own then the
// observed, then IPv6 the same way. Each once.
//
// A peer probes ten candidates at most. The public IPv4 address, which gets
// through most NATs, must not be crowded out by a machine's handful of IPv6
// addresses.
func Endpoints(local []netip.AddrPort, observed ...netip.AddrPort) []netip.AddrPort {
	var v4, v6 []netip.AddrPort
	for _, e := range append(append([]netip.AddrPort(nil), local...), observed...) {
		e = netip.AddrPortFrom(e.Addr().Unmap(), e.Port())
		if e.Addr().Is4() {
			v4 = appendNew(v4, e)
		} else {
			v6 = appendNew(v6, e)
		}
	}
	return append(v4, v6...)
}

func appendNew(s []netip.AddrPort, e netip.AddrPort) []netip.AddrPort {
	for _, x := range s {
		if x == e {
			return s
		}
	}
	return append(s, e)
}

// NetworkAddrs lists the addresses that say which networks this host is on:
// the ones LocalEndpoints would advertise — its global IPv6 ones among them,
// which tell one network from another where two hand out the same IPv4
// address. Sorted.
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
	pfxs := NetworkPrefixes()
	out := make([]netip.Addr, 0, len(pfxs))
	for _, p := range pfxs {
		out = append(out, p.Addr())
	}
	return out
}

// NetworkPrefixes is NetworkAddrs with each address's prefix length on its
// interface, which says which network it is on — 192.168.1.213/24 is on
// 192.168.1.0/24 — so a new address on the same network can be told from a
// new network. Sorted by address.
func NetworkPrefixes() []netip.Prefix {
	var out []netip.Prefix
	hostAddrs(func(a ifAddr) {
		if saysWhereWeAre(a.prefix.Addr(), a.flags) {
			out = append(out, a.prefix)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out
}

// saysWhereWeAre is NetworkAddrs' test for one address on an interface with
// the given flags.
func saysWhereWeAre(addr netip.Addr, flags net.Flags) bool {
	if !usableEndpoint(addr) {
		return false
	}
	if flags&net.FlagPointToPoint != 0 && (addr.IsPrivate() || IsMeshAddr(addr)) {
		return false
	}
	return true
}

// ula is IPv6's private range, fc00::/7.
var ula = netip.MustParsePrefix("fc00::/7")

// ifAddr is one address on one of this host's interfaces.
type ifAddr struct {
	// prefix is the address with its interface's prefix length: the address
	// is prefix.Addr(), and the network it is on prefix.Masked().
	prefix netip.Prefix
	flags  net.Flags
	iface  string
}

// hostAddrs calls fn with every address on an interface that is up, is not
// loopback, and leads somewhere other than this host.
func hostAddrs(fn func(ifAddr)) {
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
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			ones, _ := ipnet.Mask.Size()
			if addr.Is4() && ones > 32 {
				ones -= 96 // a v4 address with a v4-in-v6 mask
			}
			fn(ifAddr{prefix: netip.PrefixFrom(addr, ones), flags: iface.Flags, iface: iface.Name})
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
	case ula.Contains(addr):
		// IPv6's private range: a router's LAN-only addresses, and what VPNs
		// hand out — Tailscale's fd7a:115c:a1e0::/48 among them, which Go
		// counts as global unicast. The LAN is reached over IPv4 anyway.
		return false
	case addr.Is6() && !addr.IsGlobalUnicast():
		return false
	}
	// A global IPv6 address has no NAT in front of it, so it is a direct
	// path without any hole to punch beyond a stateful firewall's, which a
	// probe from each side opens. Disco only ever moves traffic onto a path
	// a pong has proven, and only onto a materially faster one than it has,
	// so advertising one costs a peer some probes when it does not work.
	return true
}
