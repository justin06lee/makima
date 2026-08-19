package control

import (
	"testing"

	"github.com/justin06lee/makima/internal/key"
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
