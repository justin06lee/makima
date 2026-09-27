package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/supervise"
)

// resetTree is a machine's makima laid out under a temporary root, where the
// real one would be under /.
func resetTree(t *testing.T) resetPaths {
	t.Helper()
	root := t.TempDir()
	return resetPaths{
		config:   filepath.Join(root, "etc", "makima", "node.json"),
		wholeDir: true,
		run:      filepath.Join(root, "var", "lib", "makima"),
		log:      filepath.Join(root, "var", "log", "makima"),
		resolver: filepath.Join(root, "etc", "resolver"),
		tmp:      filepath.Join(root, "tmp"),
		operator: filepath.Join(root, "home", ".config", "makima"),
	}
}

func put(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func there(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// joinedAs writes the config of a machine on the network at server.
func joinedAs(t *testing.T, path, name, server string, serverKey key.Public) *conf.File {
	t.Helper()
	mk := func() key.Private {
		k, err := key.NewPrivate()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	f := &conf.File{
		NodeKey:     mk(),
		MachineKey:  mk(),
		DiscoKey:    mk(),
		LoginServer: server,
		ServerKey:   serverKey,
		Self: netmap.Node{
			ID:        7,
			Name:      name,
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.77.0.5/32")},
		},
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := conf.Save(path, f); err != nil {
		t.Fatal(err)
	}
	return f
}

// holding makes the run directory hold a network, with the named machines
// on it.
func holding(t *testing.T, p resetPaths, names ...string) *control.Store {
	t.Helper()
	s, err := control.OpenStore(filepath.Join(p.run, "control.json"))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := s.MintAuthKey(true, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		machine, _ := key.NewPrivate()
		node, _ := key.NewPrivate()
		if _, err := s.Register(machine.Public(), &control.RegisterRequest{Name: n, NodeKey: node.Public(), AuthKey: auth.Secret}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// runReset runs a reset with nothing running and nobody to ask to forget
// the machine, for a test about what is deleted and kept.
func runReset(r *resetState) (string, error) {
	return r.run(context.Background(), nil, func(context.Context) {})
}

// fakeDaemon stands in for one of makima's processes, and writes down when it
// was stopped among everything else a reset does.
type fakeDaemon struct {
	running bool
	err     error
	name    string
	log     *[]string
}

func (f *fakeDaemon) Running() bool { return f.running }
func (f *fakeDaemon) Stop(context.Context, time.Duration) error {
	*f.log = append(*f.log, "stop "+f.name)
	if f.err != nil {
		return f.err
	}
	f.running = false
	return nil
}

// Every step that can fail comes before the machine leaves its network and
// before anything is deleted, so that a failure leaves it as it was. Review
// found the relay's stop failing after the leave, on a machine with something
// else on 3478: every run after that failed the same way, with the machine
// holding keys to a network that had already forgotten it.
func TestAResetThatCannotStopEverythingChangesNothing(t *testing.T) {
	p := resetTree(t)
	joinedAs(t, p.config, "laptop", "http://192.168.1.253:8081", key.Public{1})

	var log []string
	r := surveyReset(p)
	_, err := r.run(context.Background(), []resetDaemon{
		{proc: &fakeDaemon{running: true, name: "node", log: &log}, name: "the tunnel"},
		{proc: &fakeDaemon{running: true, name: "server", log: &log, err: errors.New("did not stop")}, name: "the network's server"},
	}, func(context.Context) { log = append(log, "leave") })

	if err == nil {
		t.Fatal("a server that would not stop did not stop the reset")
	}
	if slices.Contains(log, "leave") {
		t.Errorf("left the network before everything had stopped: %v", log)
	}
	if !there(p.config) {
		t.Error("deleted the config though a stop failed")
	}

	// The same for a copy of a held network that cannot be made: this Mac,
	// on tenet's network with an idle server of its own, and nowhere to put
	// the copy.
	log = nil
	p = resetTree(t)
	joinedAs(t, p.config, "laptop", "http://192.168.1.253:8081", key.Public{1})
	holding(t, p)
	p.tmp = filepath.Join(p.tmp, "not", "there")
	r = surveyReset(p)
	if _, err := r.run(context.Background(), nil, func(context.Context) { log = append(log, "leave") }); err == nil {
		t.Fatal("a copy that could not be made did not stop the reset")
	}
	if len(log) > 0 || !there(p.config) || !there(filepath.Join(p.run, "control.json")) {
		t.Errorf("went on after the copy failed: did %v, config there %v", log, there(p.config))
	}
}

// Something else on the relay's port — a STUN or TURN server; 3478 is theirs
// too — is not the relay, and not a reason to fail: it is left alone and the
// reset goes on, in order: everything stopped, then the leave, then the files.
func TestSomethingElseOnTheRelaysPortIsLeftAlone(t *testing.T) {
	p := resetTree(t)
	joinedAs(t, p.config, "laptop", "http://192.168.1.253:8081", key.Public{1})

	var log []string
	notOurs := fmt.Errorf("makima-relay is running but %w; stop it by hand", supervise.ErrNoProcess)
	r := surveyReset(p)
	_, err := r.run(context.Background(), []resetDaemon{
		{proc: &fakeDaemon{running: true, name: "node", log: &log}, name: "the tunnel"},
		{proc: &fakeDaemon{running: true, name: "relay", log: &log, err: notOurs}, name: "the relay", byPort: true},
	}, func(context.Context) {
		log = append(log, "leave")
		if !there(p.config) {
			t.Error("the config was deleted before the server was asked to forget the machine")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"stop node", "stop relay", "leave"}; !slices.Equal(log, want) {
		t.Errorf("did %v, want %v", log, want)
	}
	if there(p.config) {
		t.Error("the config survived")
	}

	// The tunnel is found by its own socket, which nothing else has: there
	// the same error is a reason to stop.
	log = nil
	p = resetTree(t)
	joinedAs(t, p.config, "laptop", "http://192.168.1.253:8081", key.Public{1})
	if _, err := surveyReset(p).run(context.Background(), []resetDaemon{
		{proc: &fakeDaemon{running: true, name: "node", log: &log, err: notOurs}, name: "the tunnel"},
	}, func(context.Context) {}); err == nil {
		t.Error("a tunnel whose process could not be found was taken as stopped")
	}
}

// A config somewhere of the person's choosing that makima cannot read as its
// own is not deleted, and neither is anything beside it: -config naming a
// directory, or the wrong file, would otherwise take it all.
func TestResetRefusesAChosenConfigThatIsNotMakimas(t *testing.T) {
	for name, lay := range map[string]func(t *testing.T, path string){
		"a directory":               func(t *testing.T, path string) { put(t, filepath.Join(path, "thesis.tex"), "mine") },
		"a file of somebody else's": func(t *testing.T, path string) { put(t, path, "mine") },
	} {
		t.Run(name, func(t *testing.T) {
			p := resetTree(t)
			p.config = filepath.Join(t.TempDir(), "chosen")
			p.wholeDir = false
			lay(t, p.config)

			r := surveyReset(p)
			if r.refusal() == nil {
				t.Fatal("reset would go ahead on something that is not a makima config")
			}
			for _, d := range r.doomed {
				if strings.HasPrefix(d, filepath.Dir(p.config)) {
					t.Errorf("listed %s to delete", d)
				}
			}
		})
	}
}

// A directory of makima's that is a symlink is not followed: deleting the
// link would leave the keys where it points while saying they were gone, and
// deleting where it points is deleting wherever somebody pointed it.
func TestResetDoesNotFollowASymlinkedDirectory(t *testing.T) {
	p := resetTree(t)
	elsewhere := filepath.Join(t.TempDir(), "disk", "makima")
	put(t, filepath.Join(elsewhere, "control.json"), "{}")
	if err := os.MkdirAll(filepath.Dir(p.run), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, p.run); err != nil {
		t.Fatal(err)
	}
	if surveyReset(p).refusal() == nil {
		t.Error("reset would go ahead through a symlinked /var/lib/makima")
	}

	// Nor through one inside it, where the network's keys are.
	p = resetTree(t)
	s := holding(t, p)
	joinedAs(t, p.config, "tenet", "http://192.168.1.253:8081", s.ServerKey().Public())
	state := filepath.Join(p.run, "control.json")
	moved := filepath.Join(t.TempDir(), "control.json")
	if err := os.Rename(state, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, state); err != nil {
		t.Fatal(err)
	}
	if surveyReset(p).refusal() == nil {
		t.Error("reset would go ahead with the network's state behind a symlink")
	}

	// Nor through a chosen config that is a symlink, which makima reads
	// through and would otherwise leave behind, keys and all.
	p = resetTree(t)
	real := filepath.Join(t.TempDir(), "node.json")
	joinedAs(t, real, "laptop", "http://192.168.1.253:8081", key.Public{1})
	p.config = filepath.Join(t.TempDir(), "node.json")
	p.wholeDir = false
	if err := os.Symlink(real, p.config); err != nil {
		t.Fatal(err)
	}
	if surveyReset(p).refusal() == nil {
		t.Error("reset would go ahead with a chosen config behind a symlink")
	}

	// An inbox that points somewhere is the person's: kept, not a refusal.
	p = resetTree(t)
	put(t, filepath.Join(p.run, "makimad.pid"), "1")
	if err := os.Symlink(t.TempDir(), filepath.Join(p.run, "inbox")); err != nil {
		t.Fatal(err)
	}
	r := surveyReset(p)
	if err := r.refusal(); err != nil {
		t.Errorf("a symlinked inbox stopped the reset: %v", err)
	}
	if _, err := runReset(r); err != nil {
		t.Fatal(err)
	}
	if !there(filepath.Join(p.run, "inbox")) {
		t.Error("the symlinked inbox was deleted")
	}
}

// Everything makima keeps goes — the node's keys, the server's network, the
// relay, the logs, a resolver file a dead daemon left — and nothing else does:
// not a file somebody sent here, not a resolver file that is not makima's.
func TestResetDeletesEveryTraceButTheInbox(t *testing.T) {
	p := resetTree(t)
	joinedAs(t, p.config, "laptop", "http://192.168.1.253:8081", key.Public{1})
	dir := filepath.Dir(p.config)
	put(t, p.config+".v3.bak", "{}")
	put(t, filepath.Join(dir, "update.json"), "{}")
	put(t, filepath.Join(dir, "authorized_keys"), "ssh-ed25519 AAAA")
	put(t, filepath.Join(p.run, "server-port"), "8081\n")
	put(t, filepath.Join(p.run, "relay.json"), "{}")
	put(t, filepath.Join(p.run, "makimad.pid"), "123\n")
	put(t, filepath.Join(p.run, "inbox", "report.pdf"), "%PDF")
	put(t, filepath.Join(p.log, "makimad.log"), "hello\n")
	put(t, filepath.Join(p.resolver, "makima"), "# Managed by makima. Removed when the daemon exits.\nnameserver 10.77.0.1\n")
	put(t, filepath.Join(p.resolver, "corp.example"), "nameserver 10.0.0.1\n")

	r := surveyReset(p)
	if _, err := runReset(r); err != nil {
		t.Fatal(err)
	}

	for _, gone := range []string{dir, filepath.Join(p.run, "server-port"), filepath.Join(p.run, "relay.json"),
		filepath.Join(p.run, "makimad.pid"), p.log, filepath.Join(p.resolver, "makima")} {
		if there(gone) {
			t.Errorf("%s survived the reset", gone)
		}
	}
	for _, kept := range []string{filepath.Join(p.run, "inbox", "report.pdf"), filepath.Join(p.resolver, "corp.example")} {
		if !there(kept) {
			t.Errorf("%s was deleted, and was not makima's to delete", kept)
		}
	}
}

// With nothing in the inbox to keep, the run directory goes whole, the way a
// fresh install has none.
func TestAnEmptyInboxGoesWithTheRest(t *testing.T) {
	p := resetTree(t)
	put(t, filepath.Join(p.run, "makimad.pid"), "123\n")
	if err := os.MkdirAll(filepath.Join(p.run, "inbox"), 0o700); err != nil {
		t.Fatal(err)
	}

	r := surveyReset(p)
	if !slices.Contains(r.doomed, p.run) {
		t.Fatalf("doomed = %v, want the run directory itself", r.doomed)
	}
	if _, err := runReset(r); err != nil {
		t.Fatal(err)
	}
	if there(p.run) {
		t.Error("the run directory survived")
	}
}

// A config somewhere of the person's choosing sits in a directory that may be
// theirs, so only what makima puts beside it goes — never the whole directory,
// and never an authorized_keys, which beside a config somebody chose could be
// anybody's.
func TestResetBesideAChosenConfigTouchesOnlyMakimasFiles(t *testing.T) {
	p := resetTree(t)
	home := t.TempDir()
	p.config = filepath.Join(home, "node.json")
	p.wholeDir = false
	joinedAs(t, p.config, "laptop", "", key.Public{})
	put(t, p.config+".v2.bak", "{}")
	put(t, filepath.Join(home, "update.json"), "{}")
	put(t, filepath.Join(home, "authorized_keys"), "ssh-ed25519 AAAA")
	put(t, filepath.Join(home, "notes.txt"), "mine")
	// A name makima uses, on something that is not the file makima makes.
	put(t, filepath.Join(home, "node.json.v1.bak", "draft.txt"), "mine")

	if _, err := runReset(surveyReset(p)); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{p.config, p.config + ".v2.bak", filepath.Join(home, "update.json")} {
		if there(gone) {
			t.Errorf("%s survived the reset", gone)
		}
	}
	for _, kept := range []string{home, filepath.Join(home, "authorized_keys"), filepath.Join(home, "notes.txt"),
		filepath.Join(home, "node.json.v1.bak", "draft.txt")} {
		if !there(kept) {
			t.Errorf("%s was deleted, and was not makima's to delete", kept)
		}
	}
}

// Only a server somewhere else is asked to forget this machine. A network this
// machine holds is being deleted along with it — this Mac, which is on tenet's
// network and also has an idle server of its own, still has to leave tenet's.
func TestResetAsksOnlyAServerItDoesNotHold(t *testing.T) {
	t.Run("on a network held elsewhere", func(t *testing.T) {
		p := resetTree(t)
		joinedAs(t, p.config, "laptop", "http://192.168.1.253:8081", key.Public{1})
		if !surveyReset(p).leaves() {
			t.Error("a machine on another machine's network did not ask to leave it")
		}
	})
	t.Run("holding an idle network of its own besides", func(t *testing.T) {
		p := resetTree(t)
		joinedAs(t, p.config, "laptop", "http://192.168.1.253:8081", key.Public{1})
		holding(t, p)
		if !surveyReset(p).leaves() {
			t.Error("an idle server here stopped this machine leaving the network it is actually on")
		}
	})
	t.Run("on the network it holds", func(t *testing.T) {
		p := resetTree(t)
		s := holding(t, p)
		joinedAs(t, p.config, "tenet", "http://192.168.1.253:8081", s.ServerKey().Public())
		if surveyReset(p).leaves() {
			t.Error("asked a server that is about to be deleted to forget this machine")
		}
	})
	t.Run("on a mesh with no server", func(t *testing.T) {
		p := resetTree(t)
		joinedAs(t, p.config, "laptop", "", key.Public{})
		if surveyReset(p).leaves() {
			t.Error("asked for a server a mesh without one does not have")
		}
	})
}

// The machine the network's server forgets is this one, and the others drop
// it: the whole point of asking, over the config's own keys and address.
func TestResetHasTheServerForgetThisMachine(t *testing.T) {
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "control.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(control.NewServer(store, log.New(io.Discard, "", 0)).Handler())
	t.Cleanup(srv.Close)
	auth, _ := store.MintAuthKey(true, 0)

	p := resetTree(t)
	f := joinedAs(t, p.config, "laptop", srv.URL, store.ServerKey().Public())
	if _, err := store.Register(f.MachineKey.Public(), &control.RegisterRequest{
		Name: "laptop", NodeKey: f.NodeKey.Public(), AuthKey: auth.Secret,
	}); err != nil {
		t.Fatal(err)
	}
	other, _ := key.NewPrivate()
	otherNode, _ := key.NewPrivate()
	if _, err := store.Register(other.Public(), &control.RegisterRequest{
		Name: "desktop", NodeKey: otherNode.Public(), AuthKey: auth.Secret,
	}); err != nil {
		t.Fatal(err)
	}

	r := surveyReset(p)
	if !r.leaves() {
		t.Fatal("a machine on another's network did not ask to leave it")
	}
	r.leave(context.Background())

	var names []string
	for _, n := range store.Nodes() {
		names = append(names, n.Name)
	}
	if !slices.Equal(names, []string{"desktop"}) {
		t.Errorf("after the reset the server lists %v, want only the desktop", names)
	}
}

// Ending a network other machines are on takes the word; a stray y there is
// every one of them joining again. A machine alone takes a yes.
func TestEndingANetworkOthersAreOnTakesTheWord(t *testing.T) {
	ask := func(r *resetState, typed string) bool {
		return r.confirm(strings.NewReader(typed), io.Discard)
	}

	p := resetTree(t)
	s := holding(t, p, "laptop", "desktop")
	joinedAs(t, p.config, "tenet", "http://192.168.1.253:8081", s.ServerKey().Public())
	r := surveyReset(p)
	if ask(r, "y\n") {
		t.Error("a y ended a network two other machines are on")
	}
	if !ask(r, "reset\n") {
		t.Error("typing reset did not go ahead")
	}

	alone := resetTree(t)
	joinedAs(t, alone.config, "laptop", "http://192.168.1.253:8081", key.Public{1})
	r = surveyReset(alone)
	if !ask(r, "y\n") || !ask(r, "yes\n") {
		t.Error("a yes did not reset a machine that strands nobody")
	}
	if ask(r, "\n") || ask(r, "n\n") || ask(r, "") {
		t.Error("reset without a yes")
	}

	// A server state that cannot be read may have anybody on it.
	unread := resetTree(t)
	put(t, filepath.Join(unread.run, "control.json"), "not json")
	if !surveyReset(unread).strands() {
		t.Error("an unreadable network was taken for an empty one")
	}
}

// Before it asks, a reset names the machines it would take a network away
// from — and not this one among them.
func TestResetNamesTheMachinesItStrands(t *testing.T) {
	p := resetTree(t)
	s := holding(t, p, "laptop", "desktop")
	f := joinedAs(t, p.config, "tenet", "http://192.168.1.253:8081", s.ServerKey().Public())
	node, _ := key.NewPrivate()
	auth, _ := s.MintAuthKey(true, 0)
	if _, err := s.Register(f.MachineKey.Public(), &control.RegisterRequest{Name: "tenet", NodeKey: node.Public(), AuthKey: auth.Secret}); err != nil {
		t.Fatal(err)
	}

	r := surveyReset(p)
	if got := r.others(); !slices.Equal(got, []string{"laptop", "desktop"}) {
		t.Errorf("others = %v, want laptop and desktop", got)
	}
	if d := r.describe(); !strings.Contains(d, "laptop and desktop lose their server") {
		t.Errorf("the description does not name who is stranded:\n%s", d)
	}
}

// A reset on the machine holding a network copies it aside first, root's
// alone, so a reset on the wrong machine is not every machine joining again.
// A machine that holds nothing leaves no copy: its keys are worth nothing
// once its server has forgotten it, and deleting them was the point.
func TestAHeldNetworkIsCopiedAsideFirst(t *testing.T) {
	p := resetTree(t)
	s := holding(t, p, "laptop")
	joinedAs(t, p.config, "tenet", "http://192.168.1.253:8081", s.ServerKey().Public())
	put(t, filepath.Join(p.run, "server-port"), "8081\n")
	if err := os.MkdirAll(p.tmp, 0o755); err != nil {
		t.Fatal(err)
	}

	kept, err := runReset(surveyReset(p))
	if err != nil {
		t.Fatal(err)
	}
	if kept == "" {
		t.Fatal("a held network was deleted with no copy kept")
	}
	if fi, err := os.Stat(kept); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the copy is at %s with %v, %v; want root's alone", kept, fi.Mode().Perm(), err)
	}
	for _, p := range []string{p.config, filepath.Join(p.run, "control.json"), filepath.Join(p.run, "server-port")} {
		b, err := os.ReadFile(filepath.Join(kept, p))
		if err != nil || len(bytes.TrimSpace(b)) == 0 {
			t.Errorf("the copy lacks %s: %v", p, err)
		}
	}
	if there(filepath.Join(p.run, "control.json")) {
		t.Error("the network survived the reset")
	}

	member := resetTree(t)
	joinedAs(t, member.config, "laptop", "http://192.168.1.253:8081", key.Public{1})
	if kept, err := runReset(surveyReset(member)); err != nil || kept != "" {
		t.Errorf("a machine holding nothing kept a copy at %q (%v)", kept, err)
	}
}
