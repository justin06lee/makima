package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// A machine that takes itself off the network is gone from every other
// machine's netmap, and is itself a stranger from then on. This is what keeps
// a reset machine from lingering on the others as an offline entry.
func TestALeavingMachineDropsOutOfEveryNetmap(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)

	desktop, _ := joinClient(t, store, url, "desktop", auth.Secret)
	laptop, _ := joinClient(t, store, url, "laptop", auth.Secret)

	before, err := desktop.PollMap(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Peers) != 1 {
		t.Fatalf("desktop sees %d peers before, want 1", len(before.Peers))
	}

	name, err := laptop.Leave(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if name != "laptop" {
		t.Errorf("Leave named %q, want laptop", name)
	}

	after, err := desktop.PollMap(context.Background(), before.Version, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Peers) != 0 {
		t.Errorf("the laptop left and is still in the desktop's netmap: %+v", after.Peers)
	}
	if _, err := laptop.PollMap(context.Background(), 0, nil); err == nil {
		t.Error("the laptop left and was still handed a netmap")
	}
}

// Leaving is idempotent: asking again, or asking as a machine the network
// never had, is already done — and takes nobody else with it.
func TestLeavingWhatYouAreNotOnIsAlreadyDone(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)
	joinClient(t, store, url, "desktop", auth.Secret)
	laptop, _ := joinClient(t, store, url, "laptop", auth.Secret)

	if _, err := laptop.Leave(context.Background()); err != nil {
		t.Fatal(err)
	}
	name, err := laptop.Leave(context.Background())
	if err != nil || name != "" {
		t.Errorf("leaving twice = %q, %v; want \"\", nil", name, err)
	}

	stranger, _ := key.NewPrivate()
	name, err = NewClient(url, store.ServerKey().Public(), stranger).Leave(context.Background())
	if err != nil || name != "" {
		t.Errorf("a stranger leaving = %q, %v; want \"\", nil", name, err)
	}
	if n := len(store.Nodes()); n != 1 {
		t.Errorf("%d nodes left, want only the desktop", n)
	}
}

// memberMachine registers a machine and returns its machine key, for a test
// that has to seal requests as it by hand.
func memberMachine(t *testing.T, store *Store, name string) key.Private {
	t.Helper()
	auth, _ := store.MintAuthKey(true, time.Hour)
	machine, _ := key.NewPrivate()
	node, _ := key.NewPrivate()
	if _, err := store.Register(machine.Public(), &RegisterRequest{Name: name, NodeKey: node.Public(), AuthKey: auth.Secret}); err != nil {
		t.Fatal(err)
	}
	return machine
}

// postSealed posts an envelope to path, and returns the status and — when the
// server sealed an answer to the machine — the answer.
func postSealed(t *testing.T, store *Store, url, path string, env *Envelope, machine key.Private) (int, LeaveResponse) {
	t.Helper()
	body, _ := json.Marshal(env)
	resp, err := http.Post(url+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out LeaveResponse
	if resp.StatusCode == http.StatusOK {
		var reply Envelope
		if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
			t.Fatal(err)
		}
		if err := reply.Open(&out, store.ServerKey().Public(), machine); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, out
}

// An envelope does not say which endpoint it was sealed for, and nonces are
// not tracked. So every message a machine sends — a poll every minute, over
// plain HTTP to a home server — is one somebody on the path can record, and
// posting a recorded one here must not take the machine off the network.
func TestARecordedPollCannotRemoveAMachine(t *testing.T) {
	store := newStore(t)
	h := NewServer(store, log.New(io.Discard, "", 0)).Handler()
	var recorded []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/machine/map" && recorded == nil {
			recorded, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(recorded))
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	machine := memberMachine(t, store, "laptop")
	c := NewClient(srv.URL, store.ServerKey().Public(), machine)
	if _, err := c.PollMap(context.Background(), 0, nil); err != nil {
		t.Fatal(err)
	}

	var env Envelope
	if err := json.Unmarshal(recorded, &env); err != nil {
		t.Fatal(err)
	}
	status, resp := postSealed(t, store, srv.URL, "/machine/leave", &env, machine)
	if status == http.StatusOK && resp.Error == "" {
		t.Errorf("a recorded poll was taken as a request to leave: %+v", resp)
	}
	if n := len(store.Nodes()); n != 1 {
		t.Errorf("a recorded poll took the laptop off the network (%d nodes left)", n)
	}
}

// Being recent is not enough: a request is a request to leave only when it
// says so, and says nothing else. Every other request a machine sends is read
// leniently, so one that some later version gives an "at" of its own must not
// open here as a leave.
func TestOnlyARequestThatSaysLeaveIsOne(t *testing.T) {
	store, url := testMesh(t)
	laptop := memberMachine(t, store, "laptop")

	for _, body := range []map[string]any{
		{"at": time.Now()},
		{"leave": false, "at": time.Now()},
		{"leave": true, "at": time.Now(), "version": 0},
	} {
		env, err := Seal(body, laptop.Public(), store.ServerKey().Public(), laptop)
		if err != nil {
			t.Fatal(err)
		}
		if _, resp := postSealed(t, store, url, "/machine/leave", env, laptop); resp.Error == "" {
			t.Errorf("%v was taken as a request to leave", body)
		}
	}
	if n := len(store.Nodes()); n != 1 {
		t.Errorf("something that was not a request to leave took the laptop off the network")
	}
}

// Only the holder of a machine key can seal as that machine: an envelope that
// names the laptop and was sealed by some other key does not open.
func TestAnotherKeyCannotLeaveAsAMachine(t *testing.T) {
	store, url := testMesh(t)
	laptop := memberMachine(t, store, "laptop")

	attacker, _ := key.NewPrivate()
	env, err := Seal(&LeaveRequest{Leave: true, At: time.Now()}, laptop.Public(), store.ServerKey().Public(), attacker)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := postSealed(t, store, url, "/machine/leave", env, laptop); status != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", status)
	}
	if n := len(store.Nodes()); n != 1 {
		t.Errorf("an envelope sealed by another key took the laptop off the network")
	}
}

// A genuine request to leave, replayed long after, is refused: the machine
// may have joined again under the same key since.
func TestAStaleRequestToLeaveIsRefused(t *testing.T) {
	store, url := testMesh(t)
	laptop := memberMachine(t, store, "laptop")

	for _, at := range []time.Time{time.Now().Add(-2 * leaveWindow), time.Now().Add(2 * leaveWindow), {}} {
		env, err := Seal(&LeaveRequest{Leave: true, At: at}, laptop.Public(), store.ServerKey().Public(), laptop)
		if err != nil {
			t.Fatal(err)
		}
		if _, resp := postSealed(t, store, url, "/machine/leave", env, laptop); resp.Error == "" {
			t.Errorf("a request to leave made at %v was taken as meant now", at)
		}
	}
	if n := len(store.Nodes()); n != 1 {
		t.Errorf("a stale request took the laptop off the network")
	}
}

// Expiring is what an operator does to a machine that may be stolen; the
// record it leaves is the operator's to remove, not the machine's.
func TestAnExpiredMachineCannotRemoveItself(t *testing.T) {
	store, url := testMesh(t)
	auth, _ := store.MintAuthKey(true, time.Hour)
	laptop, _ := joinClient(t, store, url, "laptop", auth.Secret)

	if err := store.ExpireNode("laptop"); err != nil {
		t.Fatal(err)
	}
	if _, err := laptop.Leave(context.Background()); err == nil {
		t.Error("an expired machine removed its own record")
	}
	if n := len(store.Nodes()); n != 1 {
		t.Errorf("%d nodes, want the expired laptop still there", n)
	}
}

// A control plane from before this request answers 404 at every address;
// the caller is told that, rather than that the server could not be reached,
// so it can say what to do instead.
func TestAnOldControlPlaneSaysMachinesCannotLeave(t *testing.T) {
	store := newStore(t)
	h := NewServer(store, log.New(io.Discard, "", 0)).Handler()
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/machine/leave" {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(old.Close)
	auth, _ := store.MintAuthKey(true, time.Hour)
	c, _ := joinClient(t, store, old.URL, "laptop", auth.Secret)

	if _, err := c.Leave(context.Background()); !errors.Is(err, ErrNoLeave) {
		t.Fatalf("err = %v, want ErrNoLeave", err)
	}
}
