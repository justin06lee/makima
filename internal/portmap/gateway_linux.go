package portmap

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
)

// Gateway finds the default router on Linux.
//
// Read from /proc/net/route rather than shelled out to `ip route`, because a
// file read has no dependency on iproute2 being installed — which it is not,
// on the minimal container images a subnet router or exit node is most likely
// to be running in.
func Gateway() (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, ErrNoGateway
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Scan() // header

	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 3 {
			continue
		}
		// Destination 00000000 is the default route; the gateway is field 2.
		if fields[1] != "00000000" {
			continue
		}

		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		// The value is little-endian in this file, which is a detail of how
		// the kernel formats it rather than anything about the address.
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], binary.LittleEndian.Uint32(raw))

		addr := netip.AddrFrom4(b)
		if addr.IsUnspecified() {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, ErrNoGateway
}
