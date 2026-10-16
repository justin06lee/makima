package hostaddr

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"unsafe"
)

// darwinV6Unusable are the in6_ifaddr flags that rule an address out:
// IN6_IFF_TENTATIVE, IN6_IFF_DUPLICATED, IN6_IFF_DETACHED and
// IN6_IFF_DEPRECATED, from <netinet6/in6_var.h>.
const darwinV6Unusable = 0x02 | 0x04 | 0x08 | 0x10

// siocgifaflagIn6 is SIOCGIFAFLAG_IN6, _IOWR('i', 73, struct in6_ifreq),
// and in6ifreqSize that struct's size: the interface name, then a union whose
// largest member — the ICMPv6 statistics — makes it 288 bytes.
const (
	siocgifaflagIn6 = 0xc1206949
	in6ifreqSize    = 288
)

func osV6Unusable(iface string, addr netip.Addr) bool {
	flags, err := darwinV6Flags(iface, addr)
	return err == nil && flags&darwinV6Unusable != 0
}

// darwinV6Flags asks the kernel for one IPv6 address's flags.
func darwinV6Flags(iface string, addr netip.Addr) (uint32, error) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	var req [in6ifreqSize]byte
	copy(req[:syscall.IFNAMSIZ-1], iface)
	// struct sockaddr_in6, at the union: length, family, port, flow info,
	// the address, scope.
	sa := req[syscall.IFNAMSIZ:]
	sa[0] = syscall.SizeofSockaddrInet6
	sa[1] = syscall.AF_INET6
	a16 := addr.As16()
	copy(sa[8:24], a16[:])

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocgifaflagIn6, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		return 0, errno
	}
	// ifru_flags6, an int at the start of the same union.
	return binary.LittleEndian.Uint32(sa[:4]), nil
}
