package netcfg

import (
	"encoding/json"
	"fmt"
	"strings"
)

// A bare nftables ruleset is configured by putting makima's accept rules into
// the chains that do the dropping.
//
// Not a table of makima's own: in nftables every base chain on a hook sees
// every packet, and a drop in any of them wins, so an accept in a separate
// table would change nothing. An accept inserted at the top of the chain that
// drops is seen first and does. Every such rule carries a comment beginning
// with nftTag, which is how makima finds its own rules again — by handle,
// never by position — and how it leaves everybody else's alone.
const nftTag = "makima"

// nftChain is a base chain hooked on input whose policy is drop.
type nftChain struct {
	Family, Table, Name string
}

// nftRule is a rule makima put somewhere.
type nftRule struct {
	nftChain
	Handle  int
	Comment string
}

// parseNFT reads `nft -j list ruleset` for the chains that drop input and the
// rules makima owns.
//
// The chains iptables-nft makes — INPUT in an ip or ip6 table called filter —
// are left out: those are iptables rules stored in nftables, and the
// iptables backend configures them the way iptables expects.
func parseNFT(js []byte) (drops []nftChain, mine []nftRule, err error) {
	var doc struct {
		Nftables []struct {
			Chain *struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Hook   string `json:"hook"`
				Policy string `json:"policy"`
			} `json:"chain"`
			Rule *struct {
				Family  string `json:"family"`
				Table   string `json:"table"`
				Chain   string `json:"chain"`
				Handle  int    `json:"handle"`
				Comment string `json:"comment"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		return nil, nil, fmt.Errorf("read the nftables ruleset: %w", err)
	}
	for _, o := range doc.Nftables {
		switch {
		case o.Chain != nil:
			c := o.Chain
			if c.Hook != "input" || c.Policy != "drop" || !nftFamily(c.Family) {
				continue
			}
			if (c.Family == "ip" || c.Family == "ip6") && c.Table == "filter" && c.Name == "INPUT" {
				continue
			}
			drops = append(drops, nftChain{c.Family, c.Table, c.Name})
		case o.Rule != nil:
			r := o.Rule
			if strings.HasPrefix(r.Comment, nftTag+" ") {
				mine = append(mine, nftRule{nftChain{r.Family, r.Table, r.Chain}, r.Handle, r.Comment})
			}
		}
	}
	return drops, mine, nil
}

// The families whose input chains see the host's own IP traffic.
func nftFamily(f string) bool { return f == "inet" || f == "ip" || f == "ip6" }

// nftIfaceComment and nftPortComment name what a rule is for, so the same
// rule is never inserted twice and only the right one is taken away.
func nftIfaceComment(iface string) string { return nftTag + " iface " + iface }
func nftPortComment(proto string, port int) string {
	return fmt.Sprintf("%s %s %d", nftTag, proto, port)
}

// missing lists the drop chains that lack a rule with this comment.
func missing(drops []nftChain, mine []nftRule, comment string) []nftChain {
	var out []nftChain
	for _, c := range drops {
		found := false
		for _, r := range mine {
			if r.nftChain == c && r.Comment == comment {
				found = true
				break
			}
		}
		if !found {
			out = append(out, c)
		}
	}
	return out
}

// nftInsertArgs is the nft command line that puts an accept at the top of a
// chain. nft joins its arguments and parses them as one statement, so the
// quoted strings carry their quotes.
func nftInsertArgs(c nftChain, match []string, comment string) []string {
	args := []string{"insert", "rule", c.Family, c.Table, c.Name}
	args = append(args, match...)
	return append(args, "accept", "comment", `"`+comment+`"`)
}
