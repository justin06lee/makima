package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

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

	pairingOpen  bool
	knockedAt    string
	pairingClose int

	ping   Ping
	pinged []string

	inboxDir string
	inboxOff bool

	sshOn   bool
	sshKeys []string
	sshUser string
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
func (f *fakeBackend) OpenPairing(seconds int) (PairingState, error) {
	if f.fail != nil {
		return PairingState{}, f.fail
	}
	f.pairingOpen = true
	return PairingState{Address: "mkp1_test", Expires: time.Now().Add(time.Duration(seconds) * time.Second)}, nil
}
func (f *fakeBackend) ClosePairing() { f.pairingClose++ }
func (f *fakeBackend) SetSSH(on bool, keys []string, user string) error {
	if f.fail != nil {
		return f.fail
	}
	f.sshOn, f.sshKeys, f.sshUser = on, keys, user
	return nil
}
func (f *fakeBackend) SetInbox(dir string, off bool) error {
	if f.fail != nil {
		return f.fail
	}
	f.inboxDir, f.inboxOff = dir, off
	return nil
}
func (f *fakeBackend) Ping(name string) (Ping, error) {
	if f.fail != nil {
		return Ping{}, f.fail
	}
	f.pinged = append(f.pinged, name)
	return f.ping, nil
}
func (f *fakeBackend) Pair(_ context.Context, address string) (PairedResult, error) {
	if f.fail != nil {
		return PairedResult{}, f.fail
	}
	f.knockedAt = address
	return PairedResult{Name: "desktop", Address: netip.MustParseAddr("100.64.0.2")}, nil
}
func (f *fakeBackend) SetExitNode(name string) error { f.exit = name; return nil }
func (f *fakeBackend) SetAdvertiseExit(bool) error   { return nil }
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

// Opening a window with no address is how a machine publishes itself.
func TestPairOpensAWindow(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, true).Handler()

	w := post(t, h, "/api/pair", PairRequest{Seconds: 60})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}

	var st PairingState
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Address != "mkp1_test" {
		t.Errorf("address is %q", st.Address)
	}
	if !b.pairingOpen {
		t.Error("the backend was never asked to open a window")
	}
}

// The same endpoint with an address knocks instead. One route, because the two
// are the same operation seen from either end.
func TestPairKnocksWhenGivenAnAddress(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, true).Handler()

	w := post(t, h, "/api/pair", PairRequest{Address: "mkp1_somebodyelse"})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if b.knockedAt != "mkp1_somebodyelse" {
		t.Errorf("knocked at %q", b.knockedAt)
	}
	if b.pairingOpen {
		t.Error("knocking at somebody else's address also opened a window here")
	}

	var res PairedResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Name != "desktop" {
		t.Errorf("paired with %q", res.Name)
	}
}

func TestPairCloseClosesTheWindow(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, true).Handler()

	if w := post(t, h, "/api/pair/close", nil); w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if b.pairingClose != 1 {
		t.Errorf("the window was closed %d times, want 1", b.pairingClose)
	}
}

// Pairing admits a machine to the data plane, so it must be behind the same
// gate as everything else that changes state — which in practice means the
// Unix socket and not a browser tab.
func TestPairIsRefusedOnAReadOnlyListener(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, false).Handler()

	for _, path := range []string{"/api/pair", "/api/pair/close"} {
		w := post(t, h, path, PairRequest{})
		if w.Code == http.StatusOK {
			t.Errorf("%s was allowed on a read-only listener", path)
		}
	}
	if b.pairingOpen || b.pairingClose != 0 || b.knockedAt != "" {
		t.Error("a read-only listener reached the backend anyway")
	}
}

// A knock that goes unanswered has to surface as an error the person can act
// on, not a silent success with an empty peer.
func TestPairReportsAFailedKnock(t *testing.T) {
	b := &fakeBackend{fail: errors.New("no answer from relay.example:3478")}
	h := NewServer(b, true).Handler()

	w := post(t, h, "/api/pair", PairRequest{Address: "mkp1_nobody"})
	if w.Code == http.StatusOK {
		t.Fatal("a failed knock returned 200")
	}
	if !strings.Contains(w.Body.String(), "no answer") {
		t.Errorf("the error did not reach the client: %s", w.Body)
	}
}

func TestPingReportsThePath(t *testing.T) {
	b := &fakeBackend{ping: Ping{
		Name:         "desktop",
		Address:      netip.MustParseAddr("100.64.0.2"),
		Direct:       true,
		Path:         "direct 203.0.113.9:41641",
		Latency:      11 * time.Millisecond,
		RelayLatency: 84 * time.Millisecond,
	}}
	h := NewServer(b, true).Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/ping?peer=desktop", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	var p Ping
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Direct || p.Latency != 11*time.Millisecond {
		t.Errorf("path did not survive the round trip: %+v", p)
	}
	// Both timings, because the gap between them is the point.
	if p.RelayLatency != 84*time.Millisecond {
		t.Errorf("the relayed timing was lost: %+v", p)
	}
	if len(b.pinged) != 1 || b.pinged[0] != "desktop" {
		t.Errorf("the backend was asked about %v", b.pinged)
	}
}

// Pinging is a read. It has to work on the web UI's listener, or the one
// question a person is most likely to have about their own network becomes a
// privileged operation.
func TestPingWorksOnAReadOnlyListener(t *testing.T) {
	b := &fakeBackend{ping: Ping{Name: "desktop"}}
	h := NewServer(b, false).Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/ping?peer=desktop", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("a read-only listener refused a ping: %d %s", w.Code, w.Body)
	}
}

func TestPingNeedsAPeer(t *testing.T) {
	h := NewServer(&fakeBackend{}, true).Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("a ping with no peer was accepted")
	}
}

// An unknown name must come back as an error the caller can print, not an
// empty result that reads as "known, and unreachable".
func TestPingReportsAnUnknownPeer(t *testing.T) {
	b := &fakeBackend{fail: errors.New(`no peer named "laptop"`)}
	h := NewServer(b, true).Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/ping?peer=laptop", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "laptop") {
		t.Errorf("the error did not name the peer: %s", w.Body)
	}
}

func TestSetInboxChangesTheDirectory(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, true).Handler()

	if w := post(t, h, "/api/inbox", InboxRequest{Dir: "/srv/incoming"}); w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if b.inboxDir != "/srv/incoming" || b.inboxOff {
		t.Errorf("inbox is %q off=%v", b.inboxDir, b.inboxOff)
	}

	if w := post(t, h, "/api/inbox", InboxRequest{Off: true}); w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if !b.inboxOff {
		t.Error("switching the inbox off did not reach the backend")
	}
}

// Choosing where another machine may write files on this one is the most
// write-shaped operation in the API, so a read-only listener must not have it.
func TestSetInboxIsRefusedOnAReadOnlyListener(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, false).Handler()

	if w := post(t, h, "/api/inbox", InboxRequest{Dir: "/tmp/anywhere"}); w.Code == http.StatusOK {
		t.Error("a read-only listener changed the inbox")
	}
	if b.inboxDir != "" {
		t.Error("a read-only listener reached the backend anyway")
	}
}

func TestSetSSHSwitchesTheServerOn(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, true).Handler()

	w := post(t, h, "/api/ssh", SSHRequest{On: true, Keys: []string{"github:you"}, User: "alex"})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if !b.sshOn || b.sshUser != "alex" {
		t.Errorf("backend got on=%v user=%q", b.sshOn, b.sshUser)
	}
	if len(b.sshKeys) != 1 || b.sshKeys[0] != "github:you" {
		t.Errorf("backend got keys %v", b.sshKeys)
	}

	if w := post(t, h, "/api/ssh", SSHRequest{On: false}); w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if b.sshOn {
		t.Error("switching the server off did not reach the backend")
	}
}

// Handing out a shell is the single most consequential thing in this API. A
// browser tab must not be able to do it.
func TestSetSSHIsRefusedOnAReadOnlyListener(t *testing.T) {
	b := &fakeBackend{}
	h := NewServer(b, false).Handler()

	if w := post(t, h, "/api/ssh", SSHRequest{On: true}); w.Code == http.StatusOK {
		t.Error("a read-only listener switched the ssh server on")
	}
	if b.sshOn {
		t.Error("a read-only listener reached the backend anyway")
	}
}

// Switching it on with no usable keys would leave a listening service nobody
// can use, so the failure has to reach the person who typed the command.
func TestSetSSHReportsWhyItWouldNotStart(t *testing.T) {
	b := &fakeBackend{fail: errors.New("no authorized keys were found")}
	h := NewServer(b, true).Handler()

	w := post(t, h, "/api/ssh", SSHRequest{On: true})
	if w.Code == http.StatusOK {
		t.Fatal("switching on with no keys returned 200")
	}
	if !strings.Contains(w.Body.String(), "authorized keys") {
		t.Errorf("the reason did not reach the client: %s", w.Body)
	}
}
