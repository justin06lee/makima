package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const (
	onionA = "aoqqpp7tzyil4hlq3umoos6atft6jvrqtosq2xy53sdgiesvgg4bqead.onion"
	onionB = "vsclqnawp5o6cn6uzznhggxyqbiq3jitmdksbg43wkhcbutdo6mnrcad.onion"
)

func TestOnionIsHandedToEveryNode(t *testing.T) {
	s := newStore(t)
	if err := s.AddControlURL("https://makima.example.dev"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOnion(onionA); err != nil {
		t.Fatal(err)
	}
	want := []string{"https://makima.example.dev", "http://" + onionA}
	if got := s.ControlURLs(); !slices.Equal(got, want) {
		t.Fatalf("ControlURLs = %v, want %v", got, want)
	}
	if got := s.Onion(); got != "http://"+onionA {
		t.Errorf("Onion() = %q", got)
	}

	// The same address again changes nothing — no netmap for every node on
	// each restart of the server.
	v := s.Version()
	if err := s.SetOnion(onionA); err != nil {
		t.Fatal(err)
	}
	if s.Version() != v {
		t.Error("setting the same onion address bumped the netmap")
	}
}

func TestNewOnionReplacesTheOld(t *testing.T) {
	s := newStore(t)
	if err := s.SetOnion(onionA); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOnion(onionB); err != nil {
		t.Fatal(err)
	}
	if got := s.ControlURLs(); !slices.Equal(got, []string{"http://" + onionB}) {
		t.Fatalf("ControlURLs = %v, want only the new onion address", got)
	}
}

func TestClearOnionKeepsTheOthers(t *testing.T) {
	s := newStore(t)
	if err := s.AddControlURL("https://makima.example.dev"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOnion(onionA); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearOnion(); err != nil {
		t.Fatal(err)
	}
	if got := s.ControlURLs(); !slices.Equal(got, []string{"https://makima.example.dev"}) {
		t.Fatalf("ControlURLs = %v", got)
	}
	if s.Onion() != "" {
		t.Error("an onion address survived ClearOnion")
	}
}

func TestOldDuckDNSNameIsForgotten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddControlURL("https://makima.example.dev"); err != nil {
		t.Fatal(err)
	}

	// What an older makima wrote with `makima-server ddns set -name tenet`
	// on a server listening on 8081.
	var raw map[string]any
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	raw["ddns"] = map[string]any{"name": "tenet", "token": "secret-token", "port": 8081}
	raw["control_urls"] = []string{"https://makima.example.dev", "http://tenet.duckdns.org:8081"}
	b, _ = json.Marshal(raw)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ControlURLs(); !slices.Equal(got, []string{"https://makima.example.dev"}) {
		t.Errorf("ControlURLs = %v, want the DuckDNS name gone and the rest kept", got)
	}
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var after map[string]any
	if err := json.Unmarshal(b, &after); err != nil {
		t.Fatal(err)
	}
	if after["ddns"] != nil {
		t.Error("the DuckDNS token is still in the state file")
	}
}
