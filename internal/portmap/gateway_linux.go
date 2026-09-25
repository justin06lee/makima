package portmap

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// DefaultRoute finds the default router on Linux, and the interface it is
// reached through.
//
// Read from /proc/net/route rather than shelled out to `ip route`, because a
// file read has no dependency on iproute2 being installed — which it is not,
// on the minimal container images a subnet router or exit node is most likely
// to be running in.
func DefaultRoute() (Route, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return Route{}, ErrNoGateway
	}
	defer f.Close()
	return parseProcRoute(f)
}

// parseProcRoute picks the default route with the lowest metric.
//
// Only a route whose destination *and* mask are zero is the default. The two
// halves an exit node installs also start at 00000000, with a mask of
// 00000080, and have no gateway; neither must be taken for the real one.
func parseProcRoute(r io.Reader) (Route, error) {
	s := bufio.NewScanner(r)
	s.Scan() // header

	best, bestMetric := Route{}, -1
	for s.Scan() {
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		fields := strings.Fields(s.Text())
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
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
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			continue
		}
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = Route{Gateway: addr, Interface: fields[0]}, metric
		}
	}
	if bestMetric < 0 {
		return Route{}, ErrNoGateway
	}
	return best, nil
}
