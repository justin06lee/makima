package localports

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// tcpListen is the state value /proc uses for a listening socket.
const tcpListen = "0A"

// listening reads the kernel's socket tables directly.
//
// Directly, rather than shelling out to ss or netstat, because this runs every
// few seconds for the life of the daemon: a file read costs nothing, and a
// subprocess would make the daemon's behaviour depend on which net-tools
// package the distribution happens to ship.
func listening() ([]Listener, error) {
	var out []Listener
	var inodes []string

	for _, f := range []struct {
		path string
		v6   bool
	}{
		{"/proc/net/tcp", false},
		{"/proc/net/tcp6", true},
	} {
		ls, ins, err := parseProcNet(f.path, f.v6)
		if err != nil {
			// tcp6 is absent on a kernel built without IPv6, which is not a
			// failure — the v4 table alone is a complete answer there.
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		out = append(out, ls...)
		inodes = append(inodes, ins...)
	}

	// Names are a courtesy. If the scan fails — a hardened /proc, a container
	// without visibility into other namespaces — the ports are still right.
	if names := processNames(inodes); len(names) > 0 {
		for i := range out {
			if n, ok := names[inodes[i]]; ok {
				out[i].Process = n
			}
		}
	}
	return out, nil
}

// parseProcNet reads one of the kernel's TCP tables, returning the listening
// sockets and the socket inode of each, positionally aligned.
func parseProcNet(path string, v6 bool) ([]Listener, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var (
		out    []Listener
		inodes []string
	)

	sc := bufio.NewScanner(f)
	sc.Scan() // header

	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// sl, local_address, rem_address, st, ..., inode at index 9
		if len(fields) < 10 || fields[3] != tcpListen {
			continue
		}

		addr, port, err := parseHexAddr(fields[1], v6)
		if err != nil {
			continue
		}
		out = append(out, Listener{Addr: addr, Port: port})
		inodes = append(inodes, fields[9])
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("localports: read %s: %w", path, err)
	}
	return out, inodes, nil
}

// parseHexAddr decodes the "ADDRESS:PORT" field, which is hex and in host byte
// order — so on a little-endian machine each 32-bit word reads backwards.
func parseHexAddr(s string, v6 bool) (netip.Addr, uint16, error) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("localports: %q is not addr:port", s)
	}

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}

	raw, err := hex.DecodeString(host)
	if err != nil {
		return netip.Addr{}, 0, err
	}

	want := 4
	if v6 {
		want = 16
	}
	if len(raw) != want {
		return netip.Addr{}, 0, fmt.Errorf("localports: address %q is %d bytes, want %d", host, len(raw), want)
	}

	// Each 4-byte group is a native-endian u32.
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(raw[i:i+4], binary.LittleEndian.Uint32(raw[i:i+4]))
	}

	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("localports: %q is not an address", host)
	}
	return addr.Unmap(), uint16(port), nil
}

// processNames maps socket inodes to the command holding them, by walking
// /proc for file descriptors that point at "socket:[N]".
//
// Bounded by only looking for inodes that were actually asked about, and by
// giving up on any process it cannot read rather than failing the whole scan —
// which happens constantly and harmlessly, since processes exit while it runs.
func processNames(inodes []string) map[string]string {
	if len(inodes) == 0 {
		return nil
	}

	want := make(map[string]bool, len(inodes))
	for _, in := range inodes {
		want[in] = true
	}

	names := make(map[string]string, len(inodes))

	pids, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return names
	}

	for _, pid := range pids {
		fds, err := os.ReadDir(filepath.Join(pid, "fd"))
		if err != nil {
			continue // not ours to read, or it exited mid-walk
		}

		var comm string
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(pid, "fd", fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := strings.CutPrefix(link, "socket:[")
			if !ok {
				continue
			}
			inode = strings.TrimSuffix(inode, "]")
			if !want[inode] {
				continue
			}
			if comm == "" {
				b, err := os.ReadFile(filepath.Join(pid, "comm"))
				if err != nil {
					break
				}
				comm = strings.TrimSpace(string(b))
			}
			names[inode] = comm
		}
	}
	return names
}
