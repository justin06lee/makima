package bypass

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// bindSocket scopes a socket to one interface with IP_BOUND_IF or
// IPV6_BOUND_IF, whichever its family takes; an index of zero unscopes it.
// Both set the same binding in the kernel, so a dual-stack socket's IPv4
// traffic is scoped by the IPv6 option too.
func bindSocket(c syscall.RawConn, ifc *Interface) error {
	idx := 0
	if ifc != nil {
		idx = ifc.Index
	}
	var serr error
	err := c.Control(func(fd uintptr) {
		sa, err := unix.Getsockname(int(fd))
		if err != nil {
			serr = err
			return
		}
		switch sa.(type) {
		case *unix.SockaddrInet4:
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
		case *unix.SockaddrInet6:
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
		}
	})
	if err != nil {
		return err
	}
	return serr
}
