package hostaddr

import (
	"net/netip"
	"os"
)

func osV6Unusable(_ string, addr netip.Addr) bool {
	f, err := os.Open("/proc/net/if_inet6")
	if err != nil {
		return false
	}
	defer f.Close()
	flags, ok := parseIfInet6(f)[addr]
	return ok && flags&linuxV6Unusable != 0
}
