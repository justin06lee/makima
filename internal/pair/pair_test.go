package pair

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/key"
)

func testAddress(t *testing.T) Address {
	t.Helper()
	node, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	disco, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	return Address{
		NodeKey:   node.Public(),
		DiscoKey:  disco.Public(),
		Addr:      MeshAddr(node.Public()),
		Name:      "desktop",
		Relay:     "relay.example:3478",
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:51820")},
	}
}

func TestRoundTrip(t *testing.T) {
	want := testAddress(t)
	psk, err := key.NewShared()
	if err != nil {
		t.Fatal(err)
	}
	want.PSK = psk

	s, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, Prefix) {
		t.Errorf("encoded address %q does not start with %s", s, Prefix)
	}

	got, err := Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeKey != want.NodeKey || got.DiscoKey != want.DiscoKey {
		t.Error("keys did not survive the round trip")
	}
	if got.Addr != want.Addr || got.Name != want.Name {
		t.Error("address or name did not survive the round trip")
	}
	if got.PSK != want.PSK {
		t.Error("the preshared key did not survive the round trip")
	}
	if got.Relay != want.Relay || len(got.Endpoints) != 1 || got.Endpoints[0] != want.Endpoints[0] {
		t.Error("meeting points did not survive the round trip")
	}
}

// The encoding has to survive a human: quotes from a shell, whitespace from a
// terminal, a prefix typed in the wrong case.
func TestDecodeToleratesHumanHandling(t *testing.T) {
	s, err := Encode(testAddress(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, variant := range []string{
		"  " + s + "\n",
		`"` + s + `"`,
		"'" + s + "'",
		strings.ToUpper(Prefix) + strings.TrimPrefix(s, Prefix),
	} {
		if _, err := Decode(variant); err != nil {
			t.Errorf("Decode(%q) failed: %v", variant, err)
		}
	}
}

// A truncated address must fail loudly rather than decoding into something
// half-usable — the failure mode that made bundling everything worthwhile.
func TestDecodeRejectsDamage(t *testing.T) {
	s, err := Encode(testAddress(t))
	if err != nil {
		t.Fatal(err)
	}

	for name, bad := range map[string]string{
		"empty":             "",
		"no prefix":         "hello",
		"truncated":         s[:len(s)-20],
		"prefix on its own": Prefix,
	} {
		if _, err := Decode(bad); err == nil {
			t.Errorf("%s was accepted as a pairing address", name)
		}
	}
}

// Pasting an invite where a pairing address belongs is a likely mistake, and
// the error should say which is which rather than blaming base64.
func TestDecodeRecognisesAnInvite(t *testing.T) {
	_, err := Decode("mk1_eyJzIjoiaHR0cDovL3gifQ")
	if err == nil {
		t.Fatal("an invite was accepted as a pairing address")
	}
	if !strings.Contains(err.Error(), "invite") {
		t.Errorf("error %q does not mention that it is an invite", err)
	}
}

// An address with nowhere to meet is not an address. Refusing at encode time
// is what keeps a useless string from being handed to somebody.
func TestEncodeRefusesAnAddressWithNowhereToMeet(t *testing.T) {
	a := testAddress(t)
	a.Relay = ""
	a.Endpoints = nil

	if _, err := Encode(a); err == nil {
		t.Error("an address with no relay and no endpoints was encoded")
	}
}

func TestEncodeRequiresBothKeys(t *testing.T) {
	base := testAddress(t)

	noNode := base
	noNode.NodeKey = key.Public{}
	if _, err := Encode(noNode); err == nil {
		t.Error("an address with no node key was encoded")
	}

	noDisco := base
	noDisco.DiscoKey = key.Public{}
	if _, err := Encode(noDisco); err == nil {
		t.Error("an address with no disco key was encoded")
	}
}

// Both ends compute the same address from public information. That is the
// property that removes address negotiation from a serverless mesh entirely.
func TestMeshAddrIsDeterministicAndInRange(t *testing.T) {
	k, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	a := MeshAddr(k.Public())
	if a != MeshAddr(k.Public()) {
		t.Error("the same key produced two different addresses")
	}
	if !InMesh(a) {
		t.Errorf("%s is outside the mesh range", a)
	}
	if !a.Is4() {
		t.Errorf("%s is not an IPv4 address", a)
	}
}

// Collisions are possible in 22 bits and are handled at pairing time, but they
// must be rare enough that they are an oddity rather than a routine failure.
func TestMeshAddrsAreSpreadOut(t *testing.T) {
	seen := make(map[netip.Addr]bool)
	for range 512 {
		k, err := key.NewPrivate()
		if err != nil {
			t.Fatal(err)
		}
		a := MeshAddr(k.Public())
		if seen[a] {
			t.Fatalf("two of 512 keys derived the same address %s", a)
		}
		seen[a] = true
	}
}

// The lowest address in the range reads as a network address and gets
// special-cased by tools with no reason to, so it is never handed out.
func TestMeshAddrSkipsTheNetworkAddress(t *testing.T) {
	base := meshPrefix.Addr()
	for range 256 {
		k, err := key.NewPrivate()
		if err != nil {
			t.Fatal(err)
		}
		if MeshAddr(k.Public()) == base {
			t.Fatalf("derived the network address %s", base)
		}
	}
}

// A preshared key changes the token, which is what makes it the gate rather
// than decoration: someone holding the address without the secret cannot
// produce a token that verifies.
func TestPresharedKeyBindsTheToken(t *testing.T) {
	a := testAddress(t)
	psk, err := key.NewShared()
	if err != nil {
		t.Fatal(err)
	}

	withKey := a
	withKey.PSK = psk

	if TokenValid(a, Token(withKey)) {
		t.Error("a token computed with a preshared key verified against one without")
	}
	if TokenValid(withKey, Token(a)) {
		t.Error("a token computed without a preshared key verified against one with")
	}
	if !TokenValid(withKey, Token(withKey)) {
		t.Error("a token did not verify against the address it came from")
	}
}

// An empty token must never verify, or a knock that simply omitted one would
// be admitted.
func TestEmptyTokenNeverVerifies(t *testing.T) {
	a := testAddress(t)
	if TokenValid(a, nil) || TokenValid(a, []byte{}) {
		t.Error("an empty token verified")
	}
	if TokenEqual(nil, nil) {
		t.Error("two empty tokens compared equal")
	}
}
