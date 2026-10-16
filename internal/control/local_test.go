package control

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestLocalURLsFollowTheListener(t *testing.T) {
	held := addrs("192.168.1.213", "192.168.55.1", "2600:1700::5")
	tcp := func(s string) net.Addr { return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s)) }

	cases := []struct {
		name   string
		listen net.Addr
		want   []string
	}{
		// What makima-server serve does by default: every address, both
		// families.
		{"all", tcp("[::]:8080"), []string{"http://192.168.1.213:8080", "http://192.168.55.1:8080", "http://[2600:1700::5]:8080"}},
		{"all v4", tcp("0.0.0.0:8081"), []string{"http://192.168.1.213:8081", "http://192.168.55.1:8081"}},
		// -addr naming one address: that one, and nothing it does not
		// answer on.
		{"one", tcp("192.168.1.213:8080"), []string{"http://192.168.1.213:8080"}},
		// Behind a reverse proxy on this machine: nobody else can reach it
		// directly at all.
		{"loopback", tcp("127.0.0.1:8080"), nil},
	}
	for _, tc := range cases {
		if got := LocalURLs(tc.listen, held); !slices.Equal(got, tc.want) {
			t.Errorf("%s: LocalURLs = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The server names its own addresses first, ahead of the onion address, so
// a node at home is never sent through tor to reach a machine in the same
// room — and a node whose saved address went stale when the server's DHCP
// lease moved is told the new one.
func TestLocalURLsLeadTheAddressesNodesAreTold(t *testing.T) {
	store, live := testMesh(t)
	if err := store.SetOnion(onionA); err != nil {
		t.Fatal(err)
	}
	auth, _ := store.MintAuthKey(true, time.Hour)
	c, reg := joinClient(t, store, live, "laptop", auth.Secret)

	if !slices.Equal(reg.ControlURLs, []string{"http://" + onionA}) {
		t.Fatalf("before the server knows its addresses: %v", reg.ControlURLs)
	}

	before := store.Version()
	store.SetLocalURLs([]string{"http://192.168.1.213:8080"})
	if store.Version() == before {
		t.Error("a new local address did not wake the pollers")
	}

	m, err := c.PollMap(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://192.168.1.213:8080", "http://" + onionA}
	if !slices.Equal(m.ControlURLs, want) {
		t.Errorf("netmap control URLs = %v, want %v", m.ControlURLs, want)
	}

	_, reg2 := joinClient(t, store, live, "desk", auth.Secret)
	if !slices.Equal(reg2.ControlURLs, want) {
		t.Errorf("registration control URLs = %v, want %v", reg2.ControlURLs, want)
	}

	// The list an operator manages is still just theirs: the found ones are
	// the machine's, found again on every start, and never saved.
	if got := store.ControlURLs(); !slices.Equal(got, []string{"http://" + onionA}) {
		t.Errorf("admin ControlURLs = %v", got)
	}

	// The same addresses again are no change.
	v := store.Version()
	store.SetLocalURLs([]string{"http://192.168.1.213:8080"})
	if store.Version() != v {
		t.Error("the same local addresses bumped the netmap")
	}

	// The lease moved.
	store.SetLocalURLs([]string{"http://192.168.1.214:8080"})
	m, _ = store.NetMapFor(c.machineKey.Public())
	if want := []string{"http://192.168.1.214:8080", "http://" + onionA}; !slices.Equal(m.ControlURLs, want) {
		t.Errorf("after the address moved: %v, want %v", m.ControlURLs, want)
	}
}

// An operator's own entry for one of the machine's addresses is not named
// twice.
func TestLocalURLsAreNotNamedTwice(t *testing.T) {
	s := newStore(t)
	mk, _ := joinNamed(t, s, "laptop")
	if err := s.AddControlURL("192.168.1.213:8080"); err != nil {
		t.Fatal(err)
	}
	s.SetLocalURLs([]string{"http://192.168.1.213:8080", "http://10.0.0.5:8080"})
	m, err := s.NetMapFor(mk.Public())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://192.168.1.213:8080", "http://10.0.0.5:8080"}
	if !slices.Equal(m.ControlURLs, want) {
		t.Errorf("control URLs = %v, want %v", m.ControlURLs, want)
	}
}
