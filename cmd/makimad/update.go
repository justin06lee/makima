package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/update"
	"github.com/justin06lee/subaru"
)

// errRestart is run's way of saying the daemon should start again as
// whatever binary is now at its own path.
var errRestart = errors.New("restarting into the new version")

// installTimeout bounds one update: the download, the checks, the swap.
const installTimeout = 5 * time.Minute

// updateStatus is what this machine reports about an update, nil when there
// is nothing to say.
func (n *node) updateStatus() *netmap.UpdateStatus {
	n.updMu.Lock()
	defer n.updMu.Unlock()
	if n.updStatus == nil {
		return nil
	}
	s := *n.updStatus
	return &s
}

// setUpdateStatus changes it, and tells the control plane at once rather than
// at the next heartbeat: the person who asked for the update is watching.
func (n *node) setUpdateStatus(s *netmap.UpdateStatus) {
	n.updMu.Lock()
	n.updStatus = s
	n.updMu.Unlock()
	n.kickPoll()
}

// loadUpdateFailure picks up a failure from before this start — above all the
// one a rollback leaves — so the network hears why this machine is still on
// the old version.
func (n *node) loadUpdateFailure() {
	if n.updater == nil {
		return
	}
	if f := n.updater.Failed(); f != nil {
		n.updStatus = &netmap.UpdateStatus{Tag: f.Tag, State: netmap.UpdateFailed, Error: f.Error}
	}
}

// considerUpdate acts on the network's update order: once per order, and only
// for a release newer than this one. A development build ahead of the release
// is left alone.
func (n *node) considerUpdate(ctx context.Context, o control.UpdateOrder) {
	if n.updater == nil || n.updater.Handled(o.ID) || n.updater.Pending() != nil {
		return
	}
	if !subaru.Newer(o.Tag, version) {
		if err := n.updater.MarkHandled(o.ID, o.Tag, nil); err != nil {
			log.Printf("update: %v", err)
		}
		return
	}
	if !n.updating.CompareAndSwap(false, true) {
		return
	}
	log.Printf("update: %s asked every machine to move to %s", o.By, o.Tag)
	go n.runUpdate(ctx, o.Tag, o.ID)
}

// runUpdate installs a release and restarts into it. order is zero for an
// update of this machine alone, which no network order stands behind.
func (n *node) runUpdate(ctx context.Context, tag string, order uint64) {
	defer n.updating.Store(false)

	n.setUpdateStatus(&netmap.UpdateStatus{Tag: tag, State: netmap.UpdateInstalling})
	ictx, cancel := context.WithTimeout(ctx, installTimeout)
	err := n.updater.Install(ictx, tag, order)
	cancel()
	if err != nil {
		if order != 0 {
			_ = n.updater.MarkHandled(order, tag, err)
		}
		if errors.Is(err, update.ErrNotNewer) {
			n.setUpdateStatus(nil)
			return
		}
		log.Printf("update to %s failed: %v", tag, err)
		n.setUpdateStatus(&netmap.UpdateStatus{Tag: tag, State: netmap.UpdateFailed, Error: err.Error()})
		return
	}

	log.Printf("update: %s is in place", tag)
	asked := time.Now()
	n.setUpdateStatus(&netmap.UpdateStatus{Tag: tag, State: netmap.UpdateRestarting})

	// A moment for the control plane to hear it, so whoever is watching sees
	// this machine restarting rather than going quiet.
	if n.client != nil {
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			n.mu.Lock()
			heard := n.lastPoll.After(asked)
			n.mu.Unlock()
			if heard {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	n.restarting.Store(true)
	n.stopRun()
}

// settleUpdate records that the version now running works, once it has shown
// it can: reached the control plane, or for a node without one, stayed up.
func (n *node) settleUpdate() {
	if n.updater == nil {
		return
	}
	p := n.updater.Pending()
	if p == nil {
		return
	}
	if err := n.updater.Settle(); err != nil {
		log.Printf("update: %v", err)
		return
	}
	log.Printf("update: %s works here; the previous version's files are gone", p.To)
	n.updMu.Lock()
	n.updStatus = nil
	n.updMu.Unlock()
}

// RequestUpdate is the local API's way in: move every machine in the network
// to a release, or only this one.
func (n *node) RequestUpdate(ctx context.Context, tag string, local bool) (localapi.UpdateResult, error) {
	if n.client == nil || local {
		if n.updater.Pending() != nil {
			return localapi.UpdateResult{}, errors.New("an update is already being proven here; try again in a minute")
		}
		if !subaru.Newer(tag, version) {
			return localapi.UpdateResult{}, update.ErrNotNewer
		}
		if !n.updating.CompareAndSwap(false, true) {
			return localapi.UpdateResult{}, errors.New("an update is already running here")
		}
		log.Printf("update: moving this machine to %s", tag)
		go n.runUpdate(context.WithoutCancel(ctx), tag, 0)
		return localapi.UpdateResult{Tag: tag, Local: true}, nil
	}

	o, err := n.client.RequestUpdate(ctx, tag)
	if err != nil {
		if errors.Is(err, control.ErrNoRemoteUpdates) {
			return localapi.UpdateResult{}, localapi.ErrNoRemoteUpdates
		}
		return localapi.UpdateResult{}, err
	}
	return localapi.UpdateResult{Tag: o.Tag, Order: o.ID}, nil
}
