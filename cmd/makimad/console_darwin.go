package main

import (
	"os"
	"syscall"
)

// consoleUID is whoever is logged in at the screen.
//
// macOS hands /dev/console to the user of the current graphical session, so
// its owner is the person a menu-bar app is running for even when the daemon
// was started from a launchd job with nobody's name in its environment.
func consoleUID() (int, bool) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return 0, false
	}
	return int(st.Uid), true
}
