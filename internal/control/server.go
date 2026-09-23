package control

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/relay"
)

// pollTimeout bounds how long a map request is held open.
//
// Long-polling forever would be simpler, but intermediaries — load balancers,
// NATs, corporate proxies — silently drop idle connections, and a node whose
// poll died without telling it stops receiving updates while believing it is
// connected. Returning the current map every minute makes that failure loud:
// a missed heartbeat is a reconnect, not a silent desync.
const pollTimeout = 60 * time.Second

// Server is the coordination plane's HTTP surface.
type Server struct {
	store *Store
	log   *log.Logger

	// polls and registers bound the work an unauthenticated caller can make
	// this server do. See limit.go.
	polls     *polls
	registers *buckets

	// relay is the relay carried on this server's own port, nil when it
	// carries none.
	relay http.Handler

	// listenPort is the port this server answers on, which a DuckDNS name is
	// assumed to be forwarded to unless told otherwise.
	listenPort int
}

// SetListenPort records the port this server answers on.
func (s *Server) SetListenPort(port int) { s.listenPort = port }

// NewServer wires handlers onto a store.
func NewServer(store *Store, logger *log.Logger) *Server {
	return &Server{
		store:     store,
		log:       logger,
		polls:     newPolls(maxPolls),
		registers: newBuckets(registerBurst, registerEvery),
	}
}

// SetRelay carries a relay on this server's own port, at relay.Path, and hands
// it to every node that has no other relay assigned.
//
// This is what makes the control plane the one machine that has to be
// reachable. Every node already reaches it to learn about the others; with the
// relay on the same port, two nodes that cannot reach each other directly
// still meet here, through whatever path — a port forward, a name, a reverse
// proxy — already brought them to the control plane.
//
// It serves this network's nodes and nobody else's: the control plane is the
// membership list, and a relay on a home connection's open port has no reason
// to carry strangers' traffic.
//
// Call before Handler.
func (s *Server) SetRelay(rs *relay.Server) {
	rs.SetAllow(s.store.IsMember)
	s.relay = rs
	s.store.SetBuiltinRelay(netmap.Relay{URL: relay.Path, Key: rs.PublicKey()})
}

// Handler builds the routing table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /key", s.handleKey)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /machine/register", s.handleRegister)
	mux.HandleFunc("POST /machine/map", s.handleMap)
	mux.HandleFunc("POST /machine/update", s.handleUpdate)
	if s.relay != nil {
		mux.Handle("GET "+relay.Path, s.relay)
	}
	return mux
}

// keyResponse is the one unencrypted message in the protocol.
type keyResponse struct {
	Version   int        `json:"version"`
	ServerKey key.Public `json:"server_key"`

	// MAC is present when the key was asked for with an invite handle: a
	// MAC over the key under that invite's MAC key, which only the words can
	// derive. It is what lets a joining machine that holds the words, and
	// not the key, tell this server from an impostor.
	MAC []byte `json:"mac,omitempty"`
}

// handleKey publishes the control plane's public key so a joining node can
// seal its first request. Serving it in the clear is safe — it is a public
// key — but a node that fetches it over plain HTTP is trusting the network for
// that one round trip, which is why the join flow prefers it pinned in the
// invitation.
func (s *Server) handleKey(w http.ResponseWriter, r *http.Request) {
	resp := keyResponse{
		Version:   ProtocolVersion,
		ServerKey: s.store.ServerKey().Public(),
	}
	if handle := r.URL.Query().Get("invite"); handle != "" {
		mac, ok := s.store.InviteMAC(handle)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": "this network does not know that invite — it may have expired, or been used already",
			})
			return
		}
		resp.MAC = mac
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"nodes":   len(s.store.Nodes()),
		"version": s.store.Version(),
		"release": s.store.ServerVersion(),
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.registers.allow(r.RemoteAddr, time.Now()) {
		tooMany(w, registerEvery)
		return
	}

	env, req, ok := decode[RegisterRequest](s, w, r)
	if !ok {
		return
	}

	node, err := s.store.Register(env.MachineKey, req)
	if err != nil {
		s.log.Printf("register %q: %v", req.Name, err)
		// The failure travels sealed so only the caller learns why. An
		// observer sees an opaque body either way.
		s.reply(w, env.MachineKey, &RegisterResponse{Error: err.Error()})
		return
	}

	s.log.Printf("registered %s as %s (node %d)", node.Name, node.Address.Addr(), node.ID)
	s.reply(w, env.MachineKey, &RegisterResponse{
		NodeID:  node.ID,
		Address: node.Address,
	})
}

func (s *Server) handleMap(w http.ResponseWriter, r *http.Request) {
	// Claimed before the request is decoded and held for as long as it is
	// parked, because the parking is the cost.
	if !s.polls.take() {
		tooMany(w, pollTimeout)
		return
	}
	defer s.polls.done()

	env, req, ok := decode[MapRequest](s, w, r)
	if !ok {
		return
	}

	if _, err := s.store.Checkin(env.MachineKey, Checkin{
		Endpoints: req.Endpoints,
		Running:   req.Running,
		Update:    req.Update,
	}); err != nil {
		s.reply(w, env.MachineKey, &MapResponse{Error: err.Error()})
		return
	}

	deadline := time.After(pollTimeout)
	for {
		// Subscribe before reading, so a change landing between the two is
		// not missed. The other order sleeps through exactly the update the
		// caller was waiting for.
		changed := s.store.Changed()

		resp, err := s.store.NetMapFor(env.MachineKey)
		if err != nil {
			s.reply(w, env.MachineKey, &MapResponse{Error: err.Error()})
			return
		}
		if resp.Version > req.Version {
			s.reply(w, env.MachineKey, resp)
			return
		}

		select {
		case <-changed:
			// Loop and re-read; something moved.
		case <-deadline:
			// Heartbeat: hand back the current map even though it is
			// unchanged, so the node knows the channel is alive.
			s.reply(w, env.MachineKey, resp)
			return
		case <-r.Context().Done():
			return
		}
	}
}

// handleUpdate is a node asking for every node to move to a release.
//
// Any node may ask. An order names a release and nothing more; each node
// checks that release against the project's own published checksums and
// refuses to go backwards, so the worst a node can do by asking is move the
// network forward to a release the project published.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.registers.allow(r.RemoteAddr, time.Now()) {
		tooMany(w, registerEvery)
		return
	}
	env, req, ok := decode[UpdateRequest](s, w, r)
	if !ok {
		return
	}
	by, known := s.store.NameOf(env.MachineKey)
	if !known {
		s.reply(w, env.MachineKey, &UpdateResponse{Error: "this machine is not in the network"})
		return
	}
	order, err := s.store.RequestUpdate(by, req.Tag)
	if err != nil {
		s.reply(w, env.MachineKey, &UpdateResponse{Error: err.Error()})
		return
	}
	s.log.Printf("update: %s asked every node to move to %s (order %d)", by, order.Tag, order.ID)
	s.reply(w, env.MachineKey, &UpdateResponse{Order: order})
}

// decode reads and opens a sealed request.
func decode[T any](s *Server, w http.ResponseWriter, r *http.Request) (*Envelope, *T, bool) {
	var env Envelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&env); err != nil {
		http.Error(w, "malformed envelope", http.StatusBadRequest)
		return nil, nil, false
	}
	if env.Version != ProtocolVersion {
		http.Error(w, "unsupported protocol version", http.StatusBadRequest)
		return nil, nil, false
	}

	var req T
	if err := env.Open(&req, env.MachineKey, s.store.ServerKey()); err != nil {
		// Unauthenticated: we could not establish a channel, so there is
		// nowhere to seal a reply to.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, nil, false
	}
	return &env, &req, true
}

// reply seals v to the caller's machine key.
func (s *Server) reply(w http.ResponseWriter, to key.Public, v any) {
	env, err := Seal(v, s.store.ServerKey().Public(), to, s.store.ServerKey())
	if err != nil {
		s.log.Printf("seal reply: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, env)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
