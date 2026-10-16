package hostaddr

import (
	"bufio"
	"encoding/hex"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// v6Unusable reports whether the OS has stopped offering an IPv6 address for
// new traffic: a temporary address past its preferred lifetime, kept only for
// the connections already on it; one still being checked for a duplicate on
// the link; or a duplicate. A variable so a platform without a way to ask
// can say none are.
//
// Temporary addresses that are still preferred are kept on purpose. They are
// what outbound traffic leaves from — Linux and macOS both prefer them — and
// a stateful IPv6 firewall in front of a peer lets in only the address it saw
// leave. Advertising only the stable address would have each side probe an
// address the other's firewall had never seen this machine send from.
var v6Unusable = osV6Unusable

// linuxV6Unusable are the flags in /proc/net/if_inet6 that rule an address
// out: IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_TENTATIVE.
const linuxV6Unusable = 0x08 | 0x20 | 0x40

// parseIfInet6 reads Linux's /proc/net/if_inet6 — per line, the address in
// hex, the interface index, prefix length, scope and flags, and the
// interface name — into each address's flags.
func parseIfInet6(r io.Reader) map[netip.Addr]uint64 {
	out := make(map[netip.Addr]uint64)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 6 || len(f[0]) != 32 {
			continue
		}
		b, err := hex.DecodeString(f[0])
		if err != nil {
			continue
		}
		flags, err := strconv.ParseUint(f[4], 16, 32)
		if err != nil {
			continue
		}
		out[netip.AddrFrom16([16]byte(b))] = flags
	}
	return out
}
