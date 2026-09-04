package localports

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// listening asks lsof, because macOS has no /proc.
//
// The alternative is the private pcblist sysctl, whose layout is a C struct
// that has changed shape across releases and would have to be reproduced
// here. lsof ships with the OS, its -F output is a stable machine format
// designed for exactly this, and it names the process for free.
func listening() ([]Listener, error) {
	// Bounded: this runs on a timer, and a wedged lsof must not wedge the
	// daemon's service loop behind it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// -F pcn asks for one field per line: p=pid, c=command, n=name.
	// -nP skips DNS and service-name lookups, which are slow and would turn
	// port 80 into "http" before we could parse it as a number.
	cmd := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn")
	out, err := cmd.Output()
	if err != nil {
		// lsof exits 1 when nothing matches, which is a real answer.
		if len(out) == 0 && ctx.Err() == nil {
			return nil, nil
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("localports: lsof timed out")
		}
		return nil, fmt.Errorf("localports: lsof: %w", err)
	}
	return parseLsof(string(out)), nil
}

// parseLsof reads lsof's field output, in which a process record introduces
// the file records that follow it until the next process record.
func parseLsof(out string) []Listener {
	var (
		res     []Listener
		command string
	)

	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			command = "" // new process; its name arrives on the next line
		case 'c':
			command = line[1:]
		case 'n':
			addr, port, ok := parseLsofName(line[1:])
			if !ok {
				continue
			}
			res = append(res, Listener{Addr: addr, Port: port, Process: command})
		}
	}
	return res
}

// parseLsofName decodes the address forms lsof prints for a listening socket:
// "127.0.0.1:3000", "[::1]:3000", "*:3000", and the IPv6 wildcard "[::]:3000".
func parseLsofName(s string) (netip.Addr, uint16, bool) {
	// lsof appends "->..." for connected sockets; a listener has no peer, but
	// be defensive rather than parsing a port out of the far end.
	if i := strings.Index(s, "->"); i >= 0 {
		return netip.Addr{}, 0, false
	}

	i := strings.LastIndex(s, ":")
	if i < 0 {
		return netip.Addr{}, 0, false
	}
	host, portStr := s[:i], s[i+1:]

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}

	if host == "*" {
		return netip.AddrFrom4([4]byte{}), uint16(port), true
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	return addr.Unmap(), uint16(port), true
}
