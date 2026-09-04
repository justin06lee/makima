package invite

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
)

// Drives a real running control plane the way `makima up` does: read its key,
// mint a credential, bundle both into an invite, and decode it back.
//
// Skipped unless MAKIMA_E2E_SOCK names a live server, so the ordinary test run
// stays hermetic.
func TestAgainstARealControlPlane(t *testing.T) {
	sock := os.Getenv("MAKIMA_E2E_SOCK")
	if sock == "" {
		t.Skip("set MAKIMA_E2E_SOCK to a running server's admin socket")
	}

	admin, ok := control.DialAdmin(sock)
	if !ok {
		t.Fatalf("no server answering on %s", sock)
	}

	serverKey, err := admin.ServerKey()
	if err != nil {
		t.Fatalf("ServerKey: %v", err)
	}
	t.Logf("server key: %s", serverKey)

	ak, err := admin.MintAuthKey(false, time.Hour)
	if err != nil {
		t.Fatalf("MintAuthKey: %v", err)
	}
	t.Logf("credential: %s", ak.Secret)

	s, err := Encode(Invite{
		Server:    "http://127.0.0.1:8099",
		AuthKey:   ak.Secret,
		ServerKey: serverKey,
		Expires:   time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	t.Logf("invite (%d chars): %s", len(s), s)

	back, err := Decode(s)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if back.ServerKey != serverKey {
		t.Fatal("the server key did not survive the round trip")
	}
	if back.AuthKey != ak.Secret {
		t.Fatal("the credential did not survive the round trip")
	}
	if back.Expired() {
		t.Fatal("a fresh invite reports itself expired")
	}
	if !strings.HasPrefix(s, Prefix) {
		t.Fatal("no prefix")
	}
	t.Log("bootstrap path verified against a live server")
}

// The invite has to actually admit a machine, not merely round-trip.
//
// Performs the registration `makima join` performs — the whole exchange short
// of bringing up a tunnel, which needs root and a TUN device.
func TestAnInviteAdmitsAMachine(t *testing.T) {
	sock := os.Getenv("MAKIMA_E2E_SOCK")
	url := os.Getenv("MAKIMA_E2E_URL")
	if sock == "" || url == "" {
		t.Skip("set MAKIMA_E2E_SOCK and MAKIMA_E2E_URL")
	}

	admin, ok := control.DialAdmin(sock)
	if !ok {
		t.Fatalf("no server answering on %s", sock)
	}
	serverKey, err := admin.ServerKey()
	if err != nil {
		t.Fatal(err)
	}
	ak, err := admin.MintAuthKey(false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := Encode(Invite{
		Server: url, AuthKey: ak.Secret, ServerKey: serverKey,
		Expires: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	// From here on, only what a joining machine has: the pasted string.
	inv, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}

	nodeKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	machineKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	discoKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := control.NewClient(inv.Server, inv.ServerKey, machineKey)
	resp, err := client.Register(ctx, &control.RegisterRequest{
		Name:     "e2e-laptop",
		NodeKey:  nodeKey.Public(),
		DiscoKey: discoKey.Public(),
		AuthKey:  inv.AuthKey,
	})
	if err != nil {
		t.Fatalf("register with the invite: %v", err)
	}
	t.Logf("admitted as node %d at %s", resp.NodeID, resp.Address)

	nodes, err := admin.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Name == "e2e-laptop" {
			t.Log("the machine is on the mesh")
			return
		}
	}
	t.Fatalf("registered, but the server lists %d nodes and none is ours", len(nodes))
}
