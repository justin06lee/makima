package supervise

import (
	"os"
	"syscall"
)

// Windows nodes do not come up yet — address assignment is not wired up — but
// the tree is kept compiling for every target so that the day it is, this is
// not also broken. These are the honest minimum rather than a pretence.

func detachAttrs() *syscall.SysProcAttr { return nil }

func terminate(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func alive(pid int) bool {
	_, err := os.FindProcess(pid)
	return err == nil
}
