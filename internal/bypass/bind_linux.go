package bypass

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// bindSocket binds a socket to one device with SO_BINDTODEVICE; an empty name
// unbinds it. Route lookups for a bound socket only consider routes through
// that device, so the default-route halves pointing into the tunnel are
// passed over for the real default route.
func bindSocket(c syscall.RawConn, ifc *Interface) error {
	name := ""
	if ifc != nil {
		name = ifc.Name
	}
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.BindToDevice(int(fd), name)
	})
	if err != nil {
		return err
	}
	return serr
}
