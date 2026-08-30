package localapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/serve"
)

// fakeBackend records what it was asked to do.
type fakeBackend struct {
	status  Status
	added   []serve.Service
	removed []uint16
	exit    string
	allowed bool
	fail    error
}

func (f *fakeBackend) Status() Status { return f.status }
func (f *fakeBackend) Diagnose() Diagnosis {
	return Diagnosis{Checks: []Check{{Name: "Tunnel", OK: true}}}
}
func (f *fakeBackend) AddService(s serve.Service) error {
	if f.fail != nil {
		return f.fail
	}
	f.added = append(f.added, s)
	return nil
}
func (f *fakeBackend) RemoveService(port uint16) error {
	f.removed = append(f.removed, port)
	return nil
}
func (f *fakeBackend) SetExitNode(name string) error { f.exit = name; return nil }
func (f *fakeBackend) AllowFirewall() (netcfg.Report, error) {
	f.allowed = true
	return netcfg.Report{Backend: netcfg.BackendFirewalld, Trusted: true}, nil
}

func post(t *testing.T, h http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(b)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestStatusIsServed(t *testing.T) {
	b := &fakeBackend{status: Status{Version: "test"}}
	h := NewServer(b, true).Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var got Status
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "test" {
		t.Errorf("version %q, want test", got.Version)
	}
}

func TestServeShorthandReachesTheBackend(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, true).Handler()

	if w := post(t, h, "/api/serve", ServeRequest{Spec: "80:11434", Name: "ollama"}); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if len(b.added) != 1 {
		t.Fatalf("%d services added, want 1", len(b.added))
	}
	got := b.added[0]
	if got.Port != 80 || got.Target != "127.0.0.1:11434" || got.Name != "ollama" {
		t.Errorf("added %+v, want :80 -> 127.0.0.1:11434 named ollama", got)
	}
}

// A bare port means "publish this local port on the same mesh port", which is
// the form almost everyone uses.
func TestServeExplicitPortDefaultsToLocalhost(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, true).Handler()

	if w := post(t, h, "/api/serve", ServeRequest{Port: 11434}); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if b.added[0].Target != "127.0.0.1:11434" {
		t.Errorf("target %q, want 127.0.0.1:11434", b.added[0].Target)
	}
}

func TestServeRejectsNonsense(t *testing.T) {
	h := NewServer(&fakeBackend{}, true).Handler()
	if w := post(t, h, "/api/serve", ServeRequest{Spec: "not-a-port"}); w.Code == http.StatusOK {
		t.Error("a malformed spec was accepted")
	}
}

func TestBackendErrorsReachTheCaller(t *testing.T) {
	b := &fakeBackend{fail: errors.New("port 80 is already published")}
	h := NewServer(b, true).Handler()

	w := post(t, h, "/api/serve", ServeRequest{Spec: "80"})
	if w.Code == http.StatusOK {
		t.Fatal("a failing backend reported success")
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.Error, "already published") {
		t.Errorf("error %q does not carry the backend's reason", e.Error)
	}
}

// A read-only listener is what the web UI gets unless it is explicitly made
// writable. Reading must still work, and nothing else may.
func TestReadOnlyListenerRefusesChanges(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, false).Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Error("a read-only listener refused a read")
	}

	for _, path := range []string{"/api/serve", "/api/unserve", "/api/exit-node", "/api/firewall/allow"} {
		w := post(t, h, path, map[string]any{})
		if w.Code != http.StatusForbidden {
			t.Errorf("%s returned %d on a read-only listener, want 403", path, w.Code)
		}
	}
	if len(b.added) != 0 || len(b.removed) != 0 || b.exit != "" || b.allowed {
		t.Error("a read-only listener reached the backend")
	}
}

func TestUnserveAndExitNode(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, true).Handler()

	if w := post(t, h, "/api/unserve", ServeRequest{Port: 11434}); w.Code != http.StatusOK {
		t.Fatalf("unserve: %d", w.Code)
	}
	if len(b.removed) != 1 || b.removed[0] != 11434 {
		t.Errorf("removed %v, want [11434]", b.removed)
	}

	if w := post(t, h, "/api/exit-node", ExitNodeRequest{Name: "gateway"}); w.Code != http.StatusOK {
		t.Fatalf("exit-node: %d", w.Code)
	}
	if b.exit != "gateway" {
		t.Errorf("exit node %q, want gateway", b.exit)
	}
}

func TestUIIsServedAtRoot(t *testing.T) {
	h := NewServer(&fakeBackend{}, true).Handler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<title>makima</title>") {
		t.Error("the root path did not serve the UI")
	}
	// The page drives itself off these endpoints; a rename that broke them
	// would otherwise only show up in a browser.
	for _, want := range []string{"/api/status", "/api/doctor", "/api/serve"} {
		if !strings.Contains(body, want) {
			t.Errorf("the UI does not reference %s", want)
		}
	}
}

func TestDiagnosisOK(t *testing.T) {
	if !(Diagnosis{Checks: []Check{{OK: true}}}).OK() {
		t.Error("a passing diagnosis reported failure")
	}
	if (Diagnosis{Checks: []Check{{OK: false}}}).OK() {
		t.Error("a failing check did not fail the diagnosis")
	}
	// A warning is not a failure: "nothing is published yet" should not make
	// doctor exit non-zero.
	if !(Diagnosis{Checks: []Check{{OK: false, Warning: true}}}).OK() {
		t.Error("a warning was treated as a failure")
	}
}
