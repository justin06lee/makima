package control

import (
	"testing"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

func pair(t *testing.T) (key.Private, key.Public) {
	t.Helper()
	priv, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	return priv, priv.Public()
}

func TestSealOpenRoundTrip(t *testing.T) {
	node, nodePub := pair(t)
	server, serverPub := pair(t)

	env, err := Seal(&RegisterRequest{Name: "laptop", AuthKey: "secret"}, nodePub, serverPub, node)
	if err != nil {
		t.Fatal(err)
	}

	var got RegisterRequest
	if err := env.Open(&got, nodePub, server); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Name != "laptop" || got.AuthKey != "secret" {
		t.Errorf("payload came back as %+v", got)
	}
}

// The sealed payload must not leak its contents to anyone watching the wire.
func TestPayloadIsOpaque(t *testing.T) {
	node, nodePub := pair(t)
	_, serverPub := pair(t)

	env, err := Seal(&RegisterRequest{AuthKey: "makima_supersecret"}, nodePub, serverPub, node)
	if err != nil {
		t.Fatal(err)
	}
	if string(env.Payload) == "" {
		t.Fatal("empty payload")
	}
	for _, b := range [][]byte{env.Payload} {
		if containsSub(b, []byte("makima_supersecret")) {
			t.Error("auth key appeared in plaintext on the wire")
		}
	}
}

func containsSub(hay, needle []byte) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Decryption is the authentication step, so an envelope from the wrong key
// must fail to open rather than open with junk.
func TestWrongKeyFails(t *testing.T) {
	node, nodePub := pair(t)
	_, serverPub := pair(t)
	impostor, _ := pair(t)

	env, err := Seal(&MapRequest{Version: 7}, nodePub, serverPub, node)
	if err != nil {
		t.Fatal(err)
	}

	var got MapRequest
	if err := env.Open(&got, nodePub, impostor); err == nil {
		t.Error("an envelope opened under a key it was not sealed to")
	}
}

func TestTamperedPayloadFails(t *testing.T) {
	node, nodePub := pair(t)
	server, serverPub := pair(t)

	env, err := Seal(&MapRequest{Version: 7}, nodePub, serverPub, node)
	if err != nil {
		t.Fatal(err)
	}
	env.Payload[len(env.Payload)/2] ^= 0xff

	var got MapRequest
	if err := env.Open(&got, nodePub, server); err == nil {
		t.Error("a modified payload still authenticated")
	}
}

func TestProtocolVersionMismatch(t *testing.T) {
	node, nodePub := pair(t)
	server, serverPub := pair(t)

	env, err := Seal(&MapRequest{}, nodePub, serverPub, node)
	if err != nil {
		t.Fatal(err)
	}
	env.Version = ProtocolVersion + 1

	var got MapRequest
	if err := env.Open(&got, nodePub, server); err == nil {
		t.Error("accepted a mismatched protocol version")
	}
}

func TestBadNonceRejected(t *testing.T) {
	node, nodePub := pair(t)
	server, serverPub := pair(t)

	env, err := Seal(&MapRequest{}, nodePub, serverPub, node)
	if err != nil {
		t.Fatal(err)
	}
	env.Nonce = env.Nonce[:8]

	var got MapRequest
	if err := env.Open(&got, nodePub, server); err == nil {
		t.Error("accepted a truncated nonce")
	}
}

// A preshared key is the one secret in a netmap that the control plane must
// never be able to set. It cannot read traffic either way, but handing two
// peers mismatched keys would sever them with no error anywhere, so whatever
// the server sends is discarded before anything looks at it.
func TestMapResponseDropsServerSuppliedPresharedKeys(t *testing.T) {
	psk, err := key.NewShared()
	if err != nil {
		t.Fatal(err)
	}

	m := &MapResponse{
		Self: netmap.Node{Name: "self", PresharedKey: psk},
		Peers: []netmap.Node{
			{Name: "one", PresharedKey: psk},
			{Name: "two"},
		},
	}
	m.stripServerSuppliedSecrets()

	if !m.Self.PresharedKey.IsZero() {
		t.Error("the server set a preshared key on this node and it survived")
	}
	for _, p := range m.Peers {
		if !p.PresharedKey.IsZero() {
			t.Errorf("the server set a preshared key on peer %s and it survived", p.Name)
		}
	}

	// Everything else in the netmap has to come through untouched, or the
	// strip is doing more than it claims.
	if m.Self.Name != "self" || len(m.Peers) != 2 || m.Peers[0].Name != "one" {
		t.Errorf("stripping secrets disturbed the rest of the netmap: %+v", m)
	}
}
