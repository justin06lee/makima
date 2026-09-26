package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

// What the signing side remembers of each network's lock: the latest version
// signed there from this machine, by the network's control-plane key.
//
// A node keeps the lock it has accepted, so the server cannot tell it
// otherwise. The signing side needs the same, or the server can have the
// operator's key sign a change to a lock it has quietly rewritten — report a
// key of its own among the trusted, and the next add-key or enable signs it
// in. Every lock command follows the lock's signed versions from here.
//
// Kept apart from the key files, in one place per user, for three reasons.
// Rotating goes from one key file to another, and the second has to start
// where the first left off; a key file is never written after it is made, so
// one on a stick, behind a symlink or on read-only media stays as it is; and
// a command run under sudo does not leave the key root's.

// lockPinsPath is where: beside the default signing key, whichever key a
// command is given. A variable so tests can put it elsewhere.
var lockPinsPath = func() string {
	return filepath.Join(filepath.Dir(DefaultSigningKeyPath()), "lock-pins.json")
}

type lockPins struct {
	Networks map[string]*netmap.LockPin `json:"networks"`
}

func loadPins() (*lockPins, error) {
	p := &lockPins{Networks: map[string]*netmap.LockPin{}}
	b, err := os.ReadFile(lockPinsPath())
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", lockPinsPath(), err)
	}
	if p.Networks == nil {
		p.Networks = map[string]*netmap.LockPin{}
	}
	return p, nil
}

// pinFor is the version last signed from here in network, nil for none.
func pinFor(network key.Public) (*netmap.LockPin, error) {
	p, err := loadPins()
	if err != nil {
		return nil, err
	}
	return p.Networks[network.String()], nil
}

// rememberPin records st as the version last signed in network. It never goes
// backwards: a server that shows an older lock gets nothing signed, and
// cannot talk the record down to where it would.
func rememberPin(network key.Public, st control.LockStatement) {
	updatePins(func(p *lockPins) {
		if cur := p.Networks[network.String()]; cur != nil && cur.Epoch >= st.Epoch {
			return
		}
		p.Networks[network.String()] = &netmap.LockPin{Epoch: st.Epoch, Enabled: st.Enabled, Keys: st.Keys}
	})
}

// startPin records st as a new lock's first version, over whatever was
// remembered: 'lock init' after 'lock forget' is starting over.
func startPin(network key.Public, st control.LockStatement) {
	updatePins(func(p *lockPins) {
		p.Networks[network.String()] = &netmap.LockPin{Epoch: st.Epoch, Enabled: st.Enabled, Keys: st.Keys}
	})
}

// forgetPin drops what is remembered of network's lock.
func forgetPin(network key.Public) {
	updatePins(func(p *lockPins) { delete(p.Networks, network.String()) })
}

// updatePins applies change to the file. A file that cannot be written is
// warned about, not fatal: the version is on the server already, and saying
// so beats failing a command that did what it was asked.
func updatePins(change func(*lockPins)) {
	p, err := loadPins()
	if err == nil {
		change(p)
		err = writePrivateJSON(lockPinsPath(), p)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record the lock's version in %s: %v\n", lockPinsPath(), err)
	}
}
