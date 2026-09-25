package portmap

import "testing"

func TestRouteGetGivesTheInterface(t *testing.T) {
	const out = `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.254
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	r, err := parseRouteGet(out)
	if err != nil {
		t.Fatal(err)
	}
	if r.Interface != "en0" || r.Gateway.String() != "192.168.1.254" {
		t.Errorf("got %s via %s", r.Gateway, r.Interface)
	}
}
