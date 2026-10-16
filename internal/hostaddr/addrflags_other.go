//go:build !linux && !darwin

package hostaddr

import "net/netip"

func osV6Unusable(string, netip.Addr) bool { return false }
