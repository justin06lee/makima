package control

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "control.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustKey(t *testing.T) key.Public {
	t.Helper()
	p, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	return p.Public()
}

func join(t *testing.T, s *Store, name string) *Node {
	t.Helper()
	a, err := s.MintAuthKey(false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Register(mustKey(t), &RegisterRequest{
		Name: name, NodeKey: mustKey(t), DiscoKey: mustKey(t), AuthKey: a.Secret,
	})
	if err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	return n
}

func TestAddressesAllocateSequentially(t *testing.T) {
	s := newStore(t)
	a := join(t, s, "one")
	b := join(t, s, "two")

	if got := a.Address.Addr().String(); got != "100.64.0.1" {
		t.Errorf("first node got %s, want 100.64.0.1", got)
	}
	if got := b.Address.Addr().String(); got != "100.64.0.2" {
		t.Errorf("second node got %s, want 100.64.0.2", got)
	}
}

// An address freed by forgetting a node must be reusable, or a mesh that
// churns machines slowly leaks its range.
func TestForgottenAddressIsReused(t *testing.T) {
	s := newStore(t)
	join(t, s, "one")
	two := join(t, s, "two")

	if err := s.Forget("one"); err != nil {
		t.Fatal(err)
	}
	three := join(t, s, "three")

	if three.Address.Addr().String() != "100.64.0.1" {
		t.Errorf("reused address was %s, want 100.64.0.1", three.Address.Addr())
	}
	if two.Address.Addr().String() != "100.64.0.2" {
		t.Errorf("surviving node's address moved to %s", two.Address.Addr())
	}
}

// Re-registering under a known machine key is how a node rotates its
// WireGuard key. It must keep its identity and address, and must not need a
// fresh auth key.
func TestReRegistrationKeepsIdentity(t *testing.T) {
	s := newStore(t)
	mk := mustKey(t)

	a, _ := s.MintAuthKey(false, time.Hour)
	first, err := s.Register(mk, &RegisterRequest{
		Name: "laptop", NodeKey: mustKey(t), DiscoKey: mustKey(t), AuthKey: a.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}

	rotated := mustKey(t)
	second, err := s.Register(mk, &RegisterRequest{Name: "laptop", NodeKey: rotated, DiscoKey: mustKey(t)})
	if err != nil {
		t.Fatalf("re-registration without an auth key was refused: %v", err)
	}

	if second.ID != first.ID {
		t.Errorf("node ID changed from %d to %d", first.ID, second.ID)
	}
	if second.Address != first.Address {
		t.Errorf("address changed from %s to %s", first.Address, second.Address)
	}
	if second.NodeKey != rotated {
		t.Error("rotated node key was not stored")
	}
}

func TestAuthKeyIsSingleUse(t *testing.T) {
	s := newStore(t)
	a, _ := s.MintAuthKey(false, time.Hour)

	if _, err := s.Register(mustKey(t), &RegisterRequest{
		Name: "one", NodeKey: mustKey(t), DiscoKey: mustKey(t), AuthKey: a.Secret,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(mustKey(t), &RegisterRequest{
		Name: "two", NodeKey: mustKey(t), DiscoKey: mustKey(t), AuthKey: a.Secret,
	}); err == nil {
		t.Error("a single-use auth key admitted a second node")
	}
}

func TestReusableAuthKey(t *testing.T) {
	s := newStore(t)
	a, _ := s.MintAuthKey(true, time.Hour)

	for _, name := range []string{"one", "two", "three"} {
		if _, err := s.Register(mustKey(t), &RegisterRequest{
			Name: name, NodeKey: mustKey(t), DiscoKey: mustKey(t), AuthKey: a.Secret,
		}); err != nil {
			t.Fatalf("reusable key refused %s: %v", name, err)
		}
	}
}

// Expiry is checked against an explicit clock so the test does not depend on
// how fast the machine running it happens to be.
func TestAuthKeyValidity(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		a    AuthKey
		want bool
	}{
		{"fresh single use", AuthKey{Expires: now.Add(time.Hour)}, true},
		{"expired", AuthKey{Expires: now.Add(-time.Second)}, false},
		{"used single use", AuthKey{Expires: now.Add(time.Hour), Used: true}, false},
		{"used reusable", AuthKey{Expires: now.Add(time.Hour), Reusable: true, Used: true}, true},
		{"expired reusable", AuthKey{Expires: now.Add(-time.Second), Reusable: true}, false},
		{"no expiry", AuthKey{}, true},
	}
	for _, c := range cases {
		if got := c.a.Valid(now); got != c.want {
			t.Errorf("%s: Valid = %v, want %v", c.name, got, c.want)
		}
	}
}

// A negative lifetime is a typo, and the tempting implementation turns it into
// a credential valid forever. It must be refused outright.
func TestNegativeExpiryRefused(t *testing.T) {
	s := newStore(t)
	if _, err := s.MintAuthKey(false, -time.Minute); err == nil {
		t.Fatal("a negative lifetime was accepted")
	}
}

func TestExpiredAuthKeyRejected(t *testing.T) {
	s := newStore(t)
	a, err := s.MintAuthKey(false, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if a.Expires.After(time.Now()) {
		t.Skip("clock resolution too coarse to observe expiry")
	}

	if _, err := s.Register(mustKey(t), &RegisterRequest{
		Name: "one", NodeKey: mustKey(t), DiscoKey: mustKey(t), AuthKey: a.Secret,
	}); err == nil {
		t.Error("an expired auth key was accepted")
	}
}

func TestUnknownAuthKeyRejected(t *testing.T) {
	s := newStore(t)
	if _, err := s.Register(mustKey(t), &RegisterRequest{
		Name: "one", NodeKey: mustKey(t), DiscoKey: mustKey(t), AuthKey: "makima_nope",
	}); err == nil {
		t.Error("an unknown auth key was accepted")
	}
}

// Every registration must advance the version, or nodes long-polling on the
// previous one never learn about the new peer.
func TestVersionAdvancesOnChange(t *testing.T) {
	s := newStore(t)
	before := s.Version()
	join(t, s, "one")
	if s.Version() <= before {
		t.Error("registering a node did not advance the netmap version")
	}
}

// A poll that reports unchanged endpoints must not bump the version. If it
// did, every poll would wake every other node and the long poll would
// degenerate into a busy loop across the whole mesh.
func TestUnchangedEndpointsDoNotBump(t *testing.T) {
	s := newStore(t)
	mk := mustKey(t)

	a, _ := s.MintAuthKey(false, time.Hour)
	if _, err := s.Register(mk, &RegisterRequest{
		Name: "one", NodeKey: mustKey(t), DiscoKey: mustKey(t), AuthKey: a.Secret,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:51820")},
	}); err != nil {
		t.Fatal(err)
	}

	v := s.Version()
	changed, err := s.UpdateEndpoints(mk, []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:51820")})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("identical endpoints reported as a change")
	}
	if s.Version() != v {
		t.Error("version advanced on an unchanged endpoint report")
	}

	changed, err = s.UpdateEndpoints(mk, []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:51820")})
	if err != nil {
		t.Fatal(err)
	}
	if !changed || s.Version() == v {
		t.Error("a genuinely new endpoint did not register as a change")
	}
}

func TestChangedChannelWakes(t *testing.T) {
	s := newStore(t)
	ch := s.Changed()

	select {
	case <-ch:
		t.Fatal("change channel fired before anything changed")
	default:
	}

	join(t, s, "one")

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("change channel did not fire after a registration")
	}
}

func TestNetMapExcludesSelf(t *testing.T) {
	s := newStore(t)
	mk := mustKey(t)

	a, _ := s.MintAuthKey(false, time.Hour)
	self, err := s.Register(mk, &RegisterRequest{
		Name: "self", NodeKey: mustKey(t), DiscoKey: mustKey(t), AuthKey: a.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	join(t, s, "other")

	resp, err := s.NetMapFor(mk)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Self.ID != self.ID {
		t.Errorf("Self is node %d, want %d", resp.Self.ID, self.ID)
	}
	for _, p := range resp.Peers {
		if p.ID == self.ID {
			t.Error("the netmap listed the node as its own peer")
		}
	}
	if len(resp.Peers) != 1 {
		t.Errorf("got %d peers, want 1", len(resp.Peers))
	}
}

// State must survive a restart, or every node is evicted whenever the control
// server is updated.
func TestStatePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.json")

	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	n := join(t, s, "one")
	serverKey := s.ServerKey().Public()

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.ServerKey().Public() != serverKey {
		t.Error("the control plane's identity changed across a restart")
	}

	all := reopened.Nodes()
	if len(all) != 1 || all[0].Address != n.Address || all[0].MachineKey != n.MachineKey {
		t.Errorf("node did not survive the restart: %+v", all)
	}
}
