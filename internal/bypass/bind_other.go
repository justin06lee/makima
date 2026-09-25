//go:build !darwin && !linux

package bypass

import "syscall"

func bindSocket(c syscall.RawConn, ifc *Interface) error {
	if ifc == nil {
		return nil
	}
	return ErrUnsupported
}
