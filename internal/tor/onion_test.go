package tor

import (
	"os"
	"path/filepath"
	"testing"
)

// fixedKey is a key with the seed 0, 1, 2 … 31, and fixedHost its address —
// the one a real tor publishes it under (see TestRealTor).
func fixedKey() Key {
	var k Key
	for i := range k.seed {
		k.seed[i] = byte(i)
	}
	return k
}

const fixedHost = "aoqqpp7tzyil4hlq3umoos6atft6jvrqtosq2xy53sdgiesvgg4bqead.onion"

func TestAddressFromKey(t *testing.T) {
	if got := fixedKey().Host(); got != fixedHost {
		t.Errorf("Host() = %s, want %s", got, fixedHost)
	}
	// What ADD_ONION is handed: the expanded key, clamped.
	const blob = "ED25519-V3:OJTupJxYCu+BaTV2K+BJVZ1tFEDe3hLmoSXxhB//jm+p1xhio+V0a1cb49GHsAQQRvUuvYUMfL1f3o7jhHO2SQ=="
	if got := fixedKey().blob(); got != blob {
		t.Errorf("blob() = %s, want %s", got, blob)
	}
}

func TestIsOnion(t *testing.T) {
	for host, want := range map[string]bool{
		fixedHost:                     true,
		fixedHost + ":80":             true,
		"ABC.ONION":                   true,
		"abc.onion.":                  true,
		"192.168.1.253:8081":          false,
		"tenet.duckdns.org":           false,
		"onion.example.com":           false,
		"notonion":                    false,
		"example.onion.example.com:1": false,
	} {
		if got := IsOnion(host); got != want {
			t.Errorf("IsOnion(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestKeyKeepsItsAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "control-onion.json")
	k1, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if k1.Host() != k2.Host() {
		t.Fatalf("a second load made a new address: %s, then %s", k1.Host(), k2.Host())
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("key file is %v, want 0600", st.Mode().Perm())
	}
}

func TestBrokenKeyFileIsNotReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-onion.json")
	if err := os.WriteFile(path, []byte(`{"ed25519_seed":"AAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A new key would be a new address every node has never heard of; a
	// file that does not parse is a problem to report, not to paper over.
	if _, err := LoadKey(path); err == nil {
		t.Fatal("a short seed loaded")
	}
}
