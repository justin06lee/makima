package control

import (
	"context"
	"time"

	"github.com/justin06lee/makima/internal/netmap"
)

// presenceEvery is how often the control plane looks for nodes that went
// quiet or came back. A node counts as gone after two missed heartbeats
// (Node.Online); this only decides how soon after that everyone hears.
const presenceEvery = 10 * time.Second

// RunPresence tells every node when another one goes offline or comes back.
//
// Whether a node is online is a matter of time passing — it stops polling,
// and a couple of minutes later it counts as gone — and time passing changes
// nothing in the store. Nothing was bumped, so no node was sent a new
// netmap, and each one kept the "online" it was last given: a peer that went
// away hours ago still showed online in the app, in `makima update`'s wait
// for it, and in possess, until something unrelated happened to change.
// Noticing the transitions and publishing them as changes is what makes the
// flag mean what it says.
func RunPresence(ctx context.Context, store *Store) {
	t := time.NewTicker(presenceEvery)
	defer t.Stop()
	for {
		store.notePresence()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// notePresence publishes a new netmap if any node has gone offline or come
// back since it last looked, and reports whether one did.
func (s *Store) notePresence() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.online == nil {
		s.online = make(map[netmap.NodeID]bool, len(s.state.Nodes))
	}
	changed := false
	seen := make(map[netmap.NodeID]bool, len(s.state.Nodes))
	for _, n := range s.state.Nodes {
		now := n.Online()
		seen[n.ID] = true
		if was, ok := s.online[n.ID]; !ok || was != now {
			// The first look is not a change: every node has only just been
			// sent a netmap computed from the same clock.
			changed = changed || ok
			s.online[n.ID] = now
		}
	}
	for id := range s.online {
		if !seen[id] {
			delete(s.online, id)
		}
	}
	if changed {
		s.bump()
	}
	return changed
}
