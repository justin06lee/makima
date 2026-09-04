// Package localapi is how you ask a running daemon what it is doing, and tell
// it to do something else.
//
// It exists because the interesting state is only in the daemon. Whether a
// peer is reachable directly or through a relay, whether a published service's
// target is actually listening, whether the host firewall is quietly dropping
// tunnel traffic — none of that is in a config file, and all of it is what
// somebody asks when something is not working.
//
// One surface serves both the CLI and the web UI, over a Unix socket whose
// permissions are the whole access-control story, exactly as the control
// plane's admin socket works. The UI may additionally be exposed over TCP,
// which is opt-in and warned about, because a browser reaching this can
// reconfigure the node.
package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/serve"
)

// SocketPath is where the daemon listens for local requests.
//
// Beside the node configuration rather than in /var/run, so the socket and the
// state it exposes share a directory and a permission boundary — and so a
// machine with a read-only /var still works.
func SocketPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "makimad.sock")
}

// Status is everything the daemon knows about itself.
type Status struct {
	Version   string         `json:"version"`
	Node      NodeInfo       `json:"node"`
	Peers     []PeerInfo     `json:"peers"`
	Services  []serve.Status `json:"services"`
	Firewall  netcfg.Report  `json:"firewall"`
	Managed   bool           `json:"managed"`
	Server    string         `json:"server,omitempty"`
	Relay     RelayInfo      `json:"relay"`
	Domain    string         `json:"domain,omitempty"`
	DNSActive bool           `json:"dns_active"`
	ExitNode  string         `json:"exit_node,omitempty"`

	// Serverless says this node has no control plane and gains peers by
	// pairing. The UI and the CLI both need it to know which vocabulary to
	// use — "invite" or "pair" — for adding a machine.
	Serverless bool `json:"serverless"`

	// Pairing is the open pairing window, nil when none is open.
	Pairing *PairingState `json:"pairing,omitempty"`

	Filtering bool      `json:"filtering"`
	Dropped   uint64    `json:"dropped"`
	Since     time.Time `json:"since"`
}

// NodeInfo is this machine's own entry.
type NodeInfo struct {
	Name      string           `json:"name"`
	Address   netip.Addr       `json:"address"`
	Interface string           `json:"interface"`
	Services  []netmap.Service `json:"services,omitempty"`

	// AdvertisedRoutes are what this node has offered, Approved what came
	// back. The gap between them is the thing an operator forgot to approve,
	// and showing both is what makes that visible rather than mysterious.
	AdvertisedRoutes []netip.Prefix `json:"advertised_routes,omitempty"`
	ApprovedRoutes   []netip.Prefix `json:"approved_routes,omitempty"`
	AdvertisesExit   bool           `json:"advertises_exit"`
	ExitApproved     bool           `json:"exit_approved"`
}

// RelayInfo is the home relay's state.
type RelayInfo struct {
	URL       string `json:"url,omitempty"`
	Connected bool   `json:"connected"`
}

// PeerInfo is one peer and how this node is currently reaching it.
type PeerInfo struct {
	Name     string           `json:"name"`
	Address  netip.Addr       `json:"address"`
	Online   bool             `json:"online"`
	Path     string           `json:"path"`
	Direct   bool             `json:"direct"`
	Latency  time.Duration    `json:"latency"`
	RelayURL string           `json:"relay_url,omitempty"`
	Services []netmap.Service `json:"services,omitempty"`
	Routes   []netip.Prefix   `json:"routes,omitempty"`
	ExitNode bool             `json:"exit_node"`
}

// PairingState is an open invitation to be knocked on.
type PairingState struct {
	// Address is the string to hand to the other machine. It is regenerated
	// on every request rather than stored: two of its fields, the endpoints
	// and the relay, change underneath it.
	Address string `json:"address"`

	// Expires is when this node stops answering knocks.
	Expires time.Time `json:"expires"`
}

// PairRequest opens a window or knocks on someone else's.
type PairRequest struct {
	// Address is a pairing address to knock on. Empty means open a window
	// here instead.
	Address string `json:"address,omitempty"`

	// Seconds is how long to hold a window open. Zero means the default.
	Seconds int `json:"seconds,omitempty"`
}

// PairedResult is the machine on the other end of a completed pairing.
type PairedResult struct {
	Name    string     `json:"name"`
	Address netip.Addr `json:"address"`
}

// Ping is one probe of one peer, and what came back.
//
// Deliberately a snapshot of the path rather than a single round trip. The
// question people actually have is not "is the peer up" — `makima status`
// answers that — but "am I going through a relay, and will that ever stop",
// so both timings are reported and Direct is the headline.
type Ping struct {
	Name    string     `json:"name"`
	Address netip.Addr `json:"address"`

	// Direct says the tunnel is currently taking a direct path, and Path
	// renders it the way status does.
	Direct bool   `json:"direct"`
	Path   string `json:"path"`

	// Latency is the direct round trip, RelayLatency the relayed one. Either
	// may be zero, meaning unmeasured rather than instantaneous.
	Latency      time.Duration `json:"latency"`
	RelayLatency time.Duration `json:"relay_latency"`

	RelayURL string `json:"relay_url,omitempty"`

	// Candidates are the addresses being tried. Shown when nothing has worked
	// yet, because "which addresses did it even attempt" is the next question
	// after "it is not connecting".
	Candidates []netip.AddrPort `json:"candidates,omitempty"`
}

// Check is one diagnostic result.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`

	// Fix is the exact command that resolves it. Empty when there is nothing
	// to run — a check that fails with no fix is worse than no check at all,
	// so this is filled wherever one exists.
	Fix string `json:"fix,omitempty"`

	// Warning marks a result that is not a failure but is worth knowing, so
	// the UI can colour it differently from something that is actually broken.
	Warning bool `json:"warning,omitempty"`
}

// Diagnosis is the whole doctor run.
type Diagnosis struct {
	Checks []Check `json:"checks"`
}

// OK reports whether nothing is broken.
func (d Diagnosis) OK() bool {
	for _, c := range d.Checks {
		if !c.OK && !c.Warning {
			return false
		}
	}
	return true
}

// Backend is what the daemon implements to be inspected and driven.
type Backend interface {
	Status() Status
	Diagnose() Diagnosis

	AddService(s serve.Service) error
	RemoveService(port uint16) error

	// OpenPairing publishes a pairing address and starts answering knocks on
	// it. ClosePairing stops. Pair knocks on somebody else's, blocking until
	// it is answered or ctx expires.
	OpenPairing(seconds int) (PairingState, error)
	ClosePairing()
	Pair(ctx context.Context, address string) (PairedResult, error)

	// Ping probes one peer and reports the path to it.
	Ping(name string) (Ping, error)

	SetExitNode(name string) error
	AllowFirewall() (netcfg.Report, error)
}

// Server exposes a Backend over HTTP.
type Server struct {
	backend Backend

	// allowWrite gates the endpoints that change something.
	//
	// The Unix socket gets them; a TCP listener may not, because a browser tab
	// on a machine somebody else is using should not be able to republish this
	// node's ports. The distinction is made per-listener rather than per-route
	// so it cannot be got wrong by adding a route later.
	allowWrite bool
}

// NewServer builds a handler for a backend.
func NewServer(b Backend, allowWrite bool) *Server {
	return &Server{backend: b, allowWrite: allowWrite}
}

// Handler builds the routing table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.backend.Status())
	})

	// A GET, because probing changes nothing an observer could see. It is on
	// the read-only listener for the same reason status is: knowing whether
	// your own path is direct is not a privilege.
	mux.HandleFunc("GET /api/ping", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("peer")
		if name == "" {
			writeErr(w, http.StatusBadRequest, errors.New("ping needs a peer name"))
			return
		}
		p, err := s.backend.Ping(name)
		if err != nil {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, p)
	})

	mux.HandleFunc("GET /api/doctor", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.backend.Diagnose())
	})

	mux.HandleFunc("POST /api/serve", func(w http.ResponseWriter, r *http.Request) {
		if !s.write(w) {
			return
		}
		var req ServeRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		svc, err := req.Service()
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.backend.AddService(svc); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, okBody())
	})

	mux.HandleFunc("POST /api/unserve", func(w http.ResponseWriter, r *http.Request) {
		if !s.write(w) {
			return
		}
		var req ServeRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.backend.RemoveService(req.Port); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, okBody())
	})

	// Pairing is a write operation in the strongest sense — it admits a new
	// machine to the data plane — so it is behind the same gate as the rest,
	// which in practice means the Unix socket only.
	mux.HandleFunc("POST /api/pair", func(w http.ResponseWriter, r *http.Request) {
		if !s.write(w) {
			return
		}
		var req PairRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}

		if req.Address == "" {
			st, err := s.backend.OpenPairing(req.Seconds)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, st)
			return
		}

		// A knock blocks until the far end answers or the caller gives up, so
		// the request's own context is what bounds it. A client that hangs up
		// cancels the knock rather than leaving it running here.
		res, err := s.backend.Pair(r.Context(), req.Address)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("POST /api/pair/close", func(w http.ResponseWriter, r *http.Request) {
		if !s.write(w) {
			return
		}
		s.backend.ClosePairing()
		writeJSON(w, http.StatusOK, okBody())
	})

	mux.HandleFunc("POST /api/exit-node", func(w http.ResponseWriter, r *http.Request) {
		if !s.write(w) {
			return
		}
		var req ExitNodeRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.backend.SetExitNode(req.Name); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, okBody())
	})

	mux.HandleFunc("POST /api/firewall/allow", func(w http.ResponseWriter, r *http.Request) {
		if !s.write(w) {
			return
		}
		rep, err := s.backend.AllowFirewall()
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, rep)
	})

	mux.Handle("/", uiHandler())
	return mux
}

// write reports whether a mutating request is permitted, answering it if not.
func (s *Server) write(w http.ResponseWriter) bool {
	if s.allowWrite {
		return true
	}
	writeErr(w, http.StatusForbidden,
		errors.New("this listener is read-only; use the socket, or start the daemon with -ui-write"))
	return false
}

// ServeRequest publishes or withdraws a port.
type ServeRequest struct {
	// Spec is the CLI's shorthand — "11434", "80:11434", "80:host:port".
	Spec string `json:"spec,omitempty"`

	Name   string `json:"name,omitempty"`
	Port   uint16 `json:"port,omitempty"`
	Target string `json:"target,omitempty"`
}

// Service resolves the request into a service, accepting either the shorthand
// or the explicit fields.
func (r ServeRequest) Service() (serve.Service, error) {
	if r.Spec != "" {
		s, err := serve.ParseSpec(r.Spec)
		if err != nil {
			return serve.Service{}, err
		}
		s.Name = r.Name
		return s, nil
	}

	s := serve.Service{Name: r.Name, Port: r.Port, Target: r.Target}
	if s.Target == "" && s.Port != 0 {
		s.Target = serve.LocalTarget(s.Port)
	}
	return s, s.Validate()
}

// ExitNodeRequest selects an exit node, or clears one when Name is empty.
type ExitNodeRequest struct {
	Name string `json:"name"`
}

func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func okBody() map[string]bool { return map[string]bool{"ok": true} }
