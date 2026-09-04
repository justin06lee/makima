package main

import (
	"testing"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/serve"
)

func nodeWith(explicit, auto []serve.Service, on bool) *node {
	return &node{
		file:         &conf.File{Services: explicit},
		autoServices: auto,
		autoServe:    on,
	}
}

func svc(port uint16, name string) serve.Service {
	return serve.Service{Name: name, Port: port, Target: serve.LocalTarget(port)}
}

func autoSvc(port uint16, name string) serve.Service {
	s := svc(port, name)
	s.Auto = true
	return s
}

func TestEffectiveServices(t *testing.T) {
	for _, tc := range []struct {
		name     string
		explicit []serve.Service
		auto     []serve.Service
		on       bool
		want     []serve.Service
	}{
		{
			name: "nothing at all",
			on:   true,
			want: []serve.Service{},
		},
		{
			name: "discovered services are published",
			auto: []serve.Service{autoSvc(11434, "ollama")},
			on:   true,
			want: []serve.Service{autoSvc(11434, "ollama")},
		},
		{
			// The rule that matters. Somebody who published 80:8080 with a
			// name meant it, and the scanner's guess of 8080:8080 must not
			// replace it or bind alongside it.
			name:     "an explicit publication wins the port",
			explicit: []serve.Service{{Name: "webui", Port: 8080, Target: serve.LocalTarget(3000)}},
			auto:     []serve.Service{autoSvc(8080, "http")},
			on:       true,
			want:     []serve.Service{{Name: "webui", Port: 8080, Target: serve.LocalTarget(3000)}},
		},
		{
			name:     "the two lists merge when they do not collide",
			explicit: []serve.Service{svc(5432, "postgres")},
			auto:     []serve.Service{autoSvc(11434, "ollama")},
			on:       true,
			want:     []serve.Service{svc(5432, "postgres"), autoSvc(11434, "ollama")},
		},
		{
			// -no-auto-serve has to actually withhold them, including ones a
			// previous scan had already recorded.
			name:     "auto-serve off publishes only what was asked for",
			explicit: []serve.Service{svc(5432, "postgres")},
			auto:     []serve.Service{autoSvc(11434, "ollama")},
			on:       false,
			want:     []serve.Service{svc(5432, "postgres")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := nodeWith(tc.explicit, tc.auto, tc.on).effectiveServicesLocked()
			if len(got) != len(tc.want) {
				t.Fatalf("got %d services %v, want %d %v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("service %d: got %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// Peers see discovered services too, or auto-serve would bind a listener
// nobody is ever told about.
func TestAdvertisedServicesIncludesDiscovered(t *testing.T) {
	n := nodeWith(nil, []serve.Service{autoSvc(11434, "ollama")}, true)

	adv := n.advertisedServicesLocked()
	if len(adv) != 1 {
		t.Fatalf("advertised %d services, want 1", len(adv))
	}
	if adv[0].Port != 11434 || adv[0].Name != "ollama" {
		t.Fatalf("advertised %+v", adv[0])
	}
}

// The web UI can change this node's settings when it is writable, so it is the
// one loopback port that must never be republished onto the mesh.
func TestReservedPortsHoldsTheUI(t *testing.T) {
	n := nodeWith(nil, nil, true)
	n.uiPort = 8088

	if !n.reservedPortsLocked()[8088] {
		t.Fatal("the web UI port is not reserved")
	}

	n.uiPort = 0
	if len(n.reservedPortsLocked()) != 0 {
		t.Fatal("reserved a port with the UI switched off")
	}
}

func TestUIPort(t *testing.T) {
	for _, tc := range []struct {
		given string
		want  uint16
	}{
		{"127.0.0.1:8088", 8088},
		{"100.64.0.1:9000", 9000},
		{"[::1]:8088", 8088},
		{"", 0},
		{"not-an-address", 0},
		{"127.0.0.1:99999", 0},
	} {
		if got := uiPort(tc.given); got != tc.want {
			t.Errorf("uiPort(%q) = %d, want %d", tc.given, got, tc.want)
		}
	}
}

// A scan that finds the same thing twice must not churn: every change
// republishes to the control plane, and a false change every five seconds
// would be a heartbeat nobody asked for.
func TestSameServices(t *testing.T) {
	a := []serve.Service{autoSvc(3000, "dev"), autoSvc(11434, "ollama")}

	if !sameServices(a, []serve.Service{autoSvc(3000, "dev"), autoSvc(11434, "ollama")}) {
		t.Fatal("identical scans compared unequal")
	}
	if sameServices(a, []serve.Service{autoSvc(3000, "dev")}) {
		t.Fatal("a service disappearing went unnoticed")
	}
	if sameServices(a, []serve.Service{autoSvc(3000, "dev"), autoSvc(11434, "llama")}) {
		t.Fatal("a rename went unnoticed")
	}
	if !sameServices(nil, []serve.Service{}) {
		t.Fatal("empty and nil compared unequal")
	}
}

// Denying a port has to outlive the next scan, or "deny" means "for five
// seconds" — the scanner would find the same listener and publish it again.
func TestDeniedPortsAreReserved(t *testing.T) {
	n := nodeWith(nil, nil, true)
	n.file.DeniedPorts = []uint16{11434, 3000}

	reserved := n.reservedPortsLocked()
	if !reserved[11434] || !reserved[3000] {
		t.Fatalf("denied ports not reserved: %v", reserved)
	}
}

func TestPortListHelpers(t *testing.T) {
	if !containsPort([]uint16{1, 2, 3}, 2) {
		t.Fatal("containsPort missed a member")
	}
	if containsPort([]uint16{1, 2, 3}, 9) {
		t.Fatal("containsPort found a non-member")
	}
	if containsPort(nil, 1) {
		t.Fatal("containsPort found something in nothing")
	}

	got := dropPort([]uint16{1, 2, 3}, 2)
	if len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Fatalf("dropPort = %v, want [1 3]", got)
	}
	// Empty must come back nil so the field stays out of the JSON entirely
	// rather than persisting as an empty array.
	if dropPort([]uint16{7}, 7) != nil {
		t.Fatal("dropping the last port left a non-nil slice")
	}
	if got := dropPort([]uint16{1}, 9); len(got) != 1 {
		t.Fatalf("dropPort removed something it should not have: %v", got)
	}
}
