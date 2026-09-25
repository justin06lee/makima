package portmap

import (
	"strings"
	"testing"
)

// With an exit node in use, two routes into the tunnel sit beside the real
// default route and are more specific than it. They start at 0.0.0.0 like the
// default does, and have no gateway; neither may be mistaken for it.
func TestProcRouteIgnoresTheExitNodeHalves(t *testing.T) {
	const table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
makima0	00000000	00000000	0001	0	0	0	00000080	0	0	0
makima0	00000080	00000000	0001	0	0	0	00000080	0	0	0
wlan0	00000000	FE01A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`
	r, err := parseProcRoute(strings.NewReader(table))
	if err != nil {
		t.Fatal(err)
	}
	if r.Interface != "eth0" || r.Gateway.String() != "192.168.1.1" {
		t.Errorf("got %s via %s, want 192.168.1.1 via eth0 (the lower metric)", r.Gateway, r.Interface)
	}
}
