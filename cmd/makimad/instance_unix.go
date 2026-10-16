//go:build unix

package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// instanceLock is held for as long as this daemon runs. Kept in a variable
// because a file nothing refers to is closed by its finalizer, and the lock
// with it.
var instanceLock *os.File

// holdInstance makes this the only makimad on the machine, waiting for any
// other to exit first.
//
// Two of them cannot both work: they want the same tunnel interface address
// and the same UDP port, and the second one used to find out only when it
// failed to bind that port and exited — after it had already counted itself
// as a start of any pending update, so that a launchd that kept restarting it
// beside a copy it did not know about rolled the update back within half a
// minute. Waiting instead costs nothing, says why once, and leaves launchd's
// copy ready to take over the moment the other one goes.
//
// The lock is an flock, which the kernel lets go of however the holder ends.
// Its descriptor is close-on-exec, so restarting into a new version in place
// lets go of it too, and the new version takes it straight back.
func holdInstance(dir string) {
	if os.Geteuid() != 0 {
		return // run refuses anyway, and says why
	}
	f, err := lockInstance(filepath.Join(dir, "makimad.lock"), func(holder string) {
		log.Printf("another makimad is already running on this machine (pid %s); waiting for it to exit rather than starting beside it", holder)
	}, time.Second)
	if err != nil {
		log.Printf("warning: %v; not checking for another makimad", err)
		return
	}
	instanceLock = f
}

// lockInstance takes the lock at path, calling waiting once with the holder's
// pid if somebody else has it, then trying again every interval until it is
// free.
func lockInstance(path string, waiting func(holder string), interval time.Duration) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	told := false
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, err
		}
		if !told {
			told = true
			b, _ := os.ReadFile(path)
			holder := strings.TrimSpace(string(b))
			if holder == "" {
				holder = "unknown"
			}
			waiting(holder)
		}
		time.Sleep(interval)
	}
	if told {
		log.Print("the other makimad has exited; starting")
	}
	// The pid is for the message above, in the next one to come along.
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return f, nil
}
