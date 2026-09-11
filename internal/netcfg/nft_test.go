package netcfg

import (
	"strings"
	"testing"
)

// The shape `nft -j list ruleset` has on an Arch box with a hand-written
// /etc/nftables.conf, plus the chains iptables-nft and Tailscale add.
const ruleset = `{"nftables": [
 {"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}},
 {"table": {"family": "inet", "name": "filter", "handle": 1}},
 {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
 {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
 {"chain": {"family": "inet", "table": "filter", "name": "output", "handle": 3, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}},
 {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 9, "comment": "makima iface makima0", "expr": []}},
 {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "expr": [{"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": null}]}},
 {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 5, "comment": "ssh", "expr": []}},
 {"table": {"family": "ip", "name": "filter", "handle": 2}},
 {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
 {"chain": {"family": "ip", "table": "filter", "name": "ts-input", "handle": 2}},
 {"table": {"family": "netdev", "name": "ingress", "handle": 3}},
 {"chain": {"family": "netdev", "table": "ingress", "name": "in", "handle": 1, "type": "filter", "hook": "ingress", "prio": 0, "policy": "drop"}}
]}`

func TestParseNFT(t *testing.T) {
	drops, mine, err := parseNFT([]byte(ruleset))
	if err != nil {
		t.Fatal(err)
	}
	if len(drops) != 1 || drops[0] != (nftChain{"inet", "filter", "input"}) {
		t.Fatalf("drop chains = %+v — only the hand-written input chain, not iptables-nft's, forward, or netdev", drops)
	}
	if len(mine) != 1 || mine[0].Handle != 9 || mine[0].Comment != nftIfaceComment("makima0") {
		t.Fatalf("makima's rules = %+v", mine)
	}
	if m := missing(drops, mine, nftIfaceComment("makima0")); len(m) != 0 {
		t.Fatalf("the interface rule is there already: %v", m)
	}
	if m := missing(drops, mine, nftPortComment("udp", 51820)); len(m) != 1 {
		t.Fatalf("the port rule is not there yet: %v", m)
	}
}

func TestParseNFTWithoutAFirewall(t *testing.T) {
	drops, mine, err := parseNFT([]byte(`{"nftables": [{"metainfo": {"version": "1.1.1"}}]}`))
	if err != nil || drops != nil || mine != nil {
		t.Fatalf("an empty ruleset: %v %v %v", drops, mine, err)
	}
	if _, _, err := parseNFT([]byte("not json")); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestNFTInsertArgs(t *testing.T) {
	got := strings.Join(nftInsertArgs(nftChain{"inet", "filter", "input"}, []string{"udp", "dport", "51820"}, nftPortComment("udp", 51820)), " ")
	want := `insert rule inet filter input udp dport 51820 accept comment "makima udp 51820"`
	if got != want {
		t.Fatalf("%s\nwant %s", got, want)
	}
}
