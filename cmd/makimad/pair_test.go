package main

import (
	"errors"
	"testing"

	"github.com/justin06lee/makima/internal/conf"
)

// A node with a control server used to be let through, because the only
// check was for makima's own socket, which a managed node has too.
func TestAManagedNodeDoesNotPair(t *testing.T) {
	n := &node{file: &conf.File{LoginServer: "http://10.0.0.1:8081"}}
	if _, _, err := n.openPairing(0); !errors.Is(err, errNotServerless) {
		t.Errorf("openPairing on a managed node: %v", err)
	}
	if _, err := n.knock(t.Context(), "mkp1_x"); !errors.Is(err, errNotServerless) {
		t.Errorf("knock on a managed node: %v", err)
	}
}

// A static mesh is told what it is, not that it has a control server.
func TestAStaticMeshIsToldWhatItIs(t *testing.T) {
	n := &node{file: &conf.File{}}
	if _, _, err := n.openPairing(0); !errors.Is(err, errStaticMesh) {
		t.Errorf("openPairing on a static mesh: %v", err)
	}
}
