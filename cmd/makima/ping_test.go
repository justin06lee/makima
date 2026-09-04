package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/localapi"
)

// The line has to say which of the two paths is in use, because that is the
// entire question. Everything else on it is detail.
func TestPingLineNamesThePath(t *testing.T) {
	direct := pingLine(localapi.Ping{
		Address: netip.MustParseAddr("100.64.0.2"),
		Direct:  true,
		Path:    "direct 203.0.113.9:41641",
		Latency: 11 * time.Millisecond,
	})
	if !strings.Contains(direct, "direct") || !strings.Contains(direct, "203.0.113.9:41641") {
		t.Errorf("a direct path rendered as %q", direct)
	}
	if !strings.Contains(direct, "11ms") {
		t.Errorf("the round trip is missing from %q", direct)
	}

	relayed := pingLine(localapi.Ping{
		Address:      netip.MustParseAddr("100.64.0.2"),
		Path:         "relay relay.example:3478",
		RelayURL:     "relay.example:3478",
		RelayLatency: 84 * time.Millisecond,
	})
	if !strings.Contains(relayed, "relay") || strings.Contains(relayed, "direct") {
		t.Errorf("a relayed path rendered as %q", relayed)
	}
}

// An unmeasured round trip must render as nothing, not as zero. "0ms" would
// read as instantaneous, which is the opposite of the truth.
func TestUnmeasuredLatencyIsBlank(t *testing.T) {
	if got := rtt(0); got != "" {
		t.Errorf("an unmeasured round trip rendered as %q", got)
	}
	if got := rtt(11 * time.Millisecond); !strings.Contains(got, "11ms") {
		t.Errorf("a measured round trip rendered as %q", got)
	}
}

// With no path at all, the useful thing to say is what is being attempted.
func TestNoPathSaysWhatItIsTrying(t *testing.T) {
	trying := pingLine(localapi.Ping{
		Address:    netip.MustParseAddr("100.64.0.2"),
		Candidates: []netip.AddrPort{netip.MustParseAddrPort("192.168.1.50:41641")},
	})
	if !strings.Contains(trying, "192.168.1.50:41641") {
		t.Errorf("a stalled ping did not name what it was trying: %q", trying)
	}

	nothing := pingLine(localapi.Ping{Address: netip.MustParseAddr("100.64.0.2")})
	if !strings.Contains(nothing, "no address to try") {
		t.Errorf("a peer with nothing to try rendered as %q", nothing)
	}
}

// A peer with neither a direct path nor a relay is genuinely broken, and the
// command should exit non-zero rather than reporting nothing cheerfully.
func TestPingSummaryFailsWithNoPathAtAll(t *testing.T) {
	err := pingSummary(localapi.Ping{Name: "desktop"}, false, time.Second, true)
	if err == nil {
		t.Error("a peer with no path at all reported success")
	}

	// A relayed peer works, even under -until-direct. Slow is not broken.
	if err := pingSummary(localapi.Ping{Name: "desktop", RelayURL: "r:3478"}, false, time.Second, true); err != nil {
		t.Errorf("a relayed peer reported failure: %v", err)
	}
}
