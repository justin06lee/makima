package wg

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

func TestUAPIOrdering(t *testing.T) {
	priv, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	ep := netip.MustParseAddrPort("192.0.2.10:51820")

	got := uapi(Config{
		PrivateKey: priv,
		ListenPort: 51820,
		Peers: []Peer{{
			PublicKey:  peerKey.Public(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
			Endpoint:   &ep,
			Keepalive:  25 * time.Second,
		}},
	})

	// replace_peers must appear before the first public_key, or wireguard-go
	// wipes the peer we just declared.
	iReplace := strings.Index(got, "replace_peers=true")
	iPeer := strings.Index(got, "public_key=")
	if iReplace == -1 || iPeer == -1 {
		t.Fatalf("missing required directives:\n%s", got)
	}
	if iReplace > iPeer {
		t.Errorf("replace_peers came after the first peer:\n%s", got)
	}

	for _, want := range []string{
		"private_key=" + priv.Hex(),
		"listen_port=51820",
		"public_key=" + peerKey.Public().Hex(),
		"allowed_ip=100.64.0.2/32",
		"endpoint=192.0.2.10:51820",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// A peer with no known path is the normal state before disco lands, and it
// must not produce an endpoint= line — wireguard-go rejects an empty one.
func TestUAPIOmitsUnknownEndpoint(t *testing.T) {
	priv, _ := key.NewPrivate()
	peerKey, _ := key.NewPrivate()

	got := uapi(Config{
		PrivateKey: priv,
		Peers: []Peer{{
			PublicKey:  peerKey.Public(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		}},
	})

	if strings.Contains(got, "endpoint=") {
		t.Errorf("emitted an endpoint for a peer with no known path:\n%s", got)
	}
	if strings.Contains(got, "persistent_keepalive_interval=") {
		t.Errorf("emitted a zero keepalive:\n%s", got)
	}
}
