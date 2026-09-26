package control

import (
	"encoding/json"
	"io"
	"net/http"
	"net/netip"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/policy"
)

// The administrative routes beyond the original three, and the client calls
// that reach them. Split from admin.go so that file stays about the socket and
// why administration goes over one at all.

// RelayRequest adds or removes a relay.
type RelayRequest struct {
	URL string     `json:"url"`
	Key key.Public `json:"key,omitzero"`
}

// DDNSRequest starts keeping a DuckDNS name pointed at this server. Port zero
// means the port the server listens on.
type DDNSRequest struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	Port  int    `json:"port,omitempty"`
}

// DDNSSetResponse is the address every node is now told about.
type DDNSSetResponse struct {
	URL string `json:"url"`
}

// ControlURLRequest adds or removes one of the server's other addresses.
type ControlURLRequest struct {
	URL string `json:"url"`
}

// RoutesRequest approves or revokes a node's advertised routes.
type RoutesRequest struct {
	Name   string         `json:"name"`
	Routes []netip.Prefix `json:"routes,omitempty"`
	Exit   bool           `json:"exit,omitempty"`
	All    bool           `json:"all,omitempty"`
}

// TagsRequest sets a node's policy tags.
type TagsRequest struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// DNSRequest configures mesh name resolution.
type DNSRequest struct {
	Enabled bool   `json:"enabled"`
	Domain  string `json:"domain,omitempty"`
}

// DNSResponse reports it.
type DNSResponse struct {
	Enabled bool   `json:"enabled"`
	Domain  string `json:"domain"`
}

// PortResponse is the port the server answers on.
type PortResponse struct {
	Port int `json:"port"`
}

// LockStatementRequest is the lock's next version, signed where the signing
// key lives, with names for any key it trusts for the first time.
type LockStatementRequest struct {
	Statement LockStatement     `json:"statement"`
	Names     map[string]string `json:"names,omitempty"`
}

// SignatureRequest records a signature for a node.
type SignatureRequest struct {
	NodeID    netmap.NodeID `json:"node_id"`
	Signature []byte        `json:"signature"`

	// LegacySignature is the old kind, for machines still on makima v0.3.0.
	// Optional: a signing tool from before it existed sends none.
	LegacySignature []byte `json:"legacy_signature,omitempty"`
}

// registerAdminRoutes attaches everything beyond the original three.
func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	post := func(path string, fn func(w http.ResponseWriter, body []byte) error) {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			body, err := readAll(r)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, adminError{err.Error()})
				return
			}
			if err := fn(w, body); err != nil {
				writeJSON(w, http.StatusBadRequest, adminError{err.Error()})
				return
			}
		})
	}

	post("/admin/relay/add", func(w http.ResponseWriter, body []byte) error {
		var req RelayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.AddRelay(req.URL, req.Key); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	post("/admin/relay/rm", func(w http.ResponseWriter, body []byte) error {
		var req RelayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.RemoveRelay(req.URL); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	post("/admin/relay/prefer", func(w http.ResponseWriter, body []byte) error {
		var req RelayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.PreferRelay(req.URL); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	mux.HandleFunc("GET /admin/relay", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.Relays())
	})

	mux.HandleFunc("GET /admin/update", func(w http.ResponseWriter, r *http.Request) {
		o, ok := s.store.UpdateOrdered()
		if !ok {
			writeJSON(w, http.StatusOK, nil)
			return
		}
		writeJSON(w, http.StatusOK, o)
	})

	post("/admin/update", func(w http.ResponseWriter, body []byte) error {
		var req UpdateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		o, err := s.store.RequestUpdate("admin", req.Tag)
		if err != nil {
			return err
		}
		s.log.Printf("update: every node asked to move to %s (order %d)", o.Tag, o.ID)
		writeJSON(w, http.StatusOK, o)
		return nil
	})

	mux.HandleFunc("GET /admin/port", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, PortResponse{Port: s.listenPort})
	})

	mux.HandleFunc("GET /admin/ddns", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.DDNSState())
	})

	post("/admin/ddns", func(w http.ResponseWriter, body []byte) error {
		var req DDNSRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		port := req.Port
		if port == 0 {
			port = s.listenPort
		}
		u, err := s.store.SetDDNS(DDNS{Name: req.Name, Token: req.Token, Port: port})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, DDNSSetResponse{URL: u})
		return nil
	})

	post("/admin/ddns/off", func(w http.ResponseWriter, body []byte) error {
		if err := s.store.ClearDDNS(); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	mux.HandleFunc("GET /admin/urls", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.ControlURLs())
	})

	post("/admin/urls/add", func(w http.ResponseWriter, body []byte) error {
		var req ControlURLRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.AddControlURL(req.URL); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	post("/admin/urls/rm", func(w http.ResponseWriter, body []byte) error {
		var req ControlURLRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.RemoveControlURL(req.URL); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	post("/admin/routes/approve", func(w http.ResponseWriter, body []byte) error {
		var req RoutesRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		routes := req.Routes
		exit := req.Exit
		if req.All {
			// Approving "all" means everything the node is advertising right
			// now, resolved here rather than by the CLI: the operator's view of
			// what is advertised may be a few seconds stale, and approving a
			// list they never saw would be worse than approving none.
			routes, exit = s.store.Advertised(req.Name)
		}
		if err := s.store.ApproveRoutes(req.Name, routes, exit); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	post("/admin/routes/revoke", func(w http.ResponseWriter, body []byte) error {
		var req RoutesRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.RevokeRoutes(req.Name, req.Routes, req.Exit); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	post("/admin/tags", func(w http.ResponseWriter, body []byte) error {
		var req TagsRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.SetTags(req.Name, req.Tags); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	post("/admin/expire", func(w http.ResponseWriter, body []byte) error {
		var req ForgetRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.ExpireNode(req.Name); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	mux.HandleFunc("GET /admin/policy", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.Policy())
	})

	post("/admin/policy", func(w http.ResponseWriter, body []byte) error {
		var p policy.Policy
		if err := json.Unmarshal(body, &p); err != nil {
			return err
		}
		if err := s.store.SetPolicy(&p); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	mux.HandleFunc("GET /admin/dns", func(w http.ResponseWriter, r *http.Request) {
		enabled, domain := s.store.DNSSettings()
		writeJSON(w, http.StatusOK, DNSResponse{Enabled: enabled, Domain: domain})
	})

	post("/admin/dns", func(w http.ResponseWriter, body []byte) error {
		var req DNSRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.SetDNS(req.Enabled, req.Domain); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	mux.HandleFunc("GET /admin/lock", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.LockStatus())
	})

	mux.HandleFunc("GET /admin/lock/pending", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.PendingSignatures())
	})

	mux.HandleFunc("GET /admin/lock/chain", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.LockChain())
	})

	post("/admin/lock/forget", func(w http.ResponseWriter, body []byte) error {
		if err := s.store.ForgetLock(); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	post("/admin/lock/statement", func(w http.ResponseWriter, body []byte) error {
		var req LockStatementRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.ApplyLockStatement(req.Statement, req.Names); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})

	post("/admin/lock/sign", func(w http.ResponseWriter, body []byte) error {
		var req SignatureRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return err
		}
		if err := s.store.ApplySignatures(req.NodeID, req.Signature, req.LegacySignature); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, okResponse())
		return nil
	})
}

func okResponse() map[string]bool { return map[string]bool{"ok": true} }

// Advertised reports what a node is currently offering to route.
func (s *Store) Advertised(name string) ([]netip.Prefix, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := s.findByName(name)
	if n == nil {
		return nil, false
	}
	return append([]netip.Prefix(nil), n.AdvertisedRoutes...), n.AdvertisesExit
}

// readAll reads a request body, capped. The cap is nominal — the socket is
// already owner-only — but an unbounded read from any source is a habit worth
// not having.
func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(io.LimitReader(r.Body, 1<<20))
}
