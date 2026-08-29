package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/policy"
)

// --- relay --------------------------------------------------------------

func relayCmd(args []string) error {
	if len(args) == 0 {
		return listRelays(nil)
	}
	switch args[0] {
	case "add":
		return addRelay(args[1:])
	case "rm", "remove":
		return removeRelay(args[1:])
	case "prefer":
		return preferRelay(args[1:])
	case "ls", "list":
		return listRelays(args[1:])
	default:
		return fmt.Errorf("unknown relay subcommand %q (try: add, rm, prefer, ls)", args[0])
	}
}

func addRelay(args []string) error {
	af := newAdminFlags("relay add")
	url := af.fs.String("url", "", "the relay's address, e.g. relay.example.com:3478")
	pubkey := af.fs.String("key", "", "the relay's public key, from 'makima-relay key'")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *url == "" {
		return fmt.Errorf("relay add needs -url")
	}

	// A relay without a pinned key is accepted but warned about. Traffic
	// through it is WireGuard-encrypted either way, so the exposure is not
	// confidentiality — it is that anything answering on that address can
	// silently discard every relayed packet, which looks exactly like a peer
	// being offline.
	var k key.Public
	if *pubkey != "" {
		if k, err = key.ParsePublic(*pubkey); err != nil {
			return fmt.Errorf("parse -key: %w", err)
		}
	}

	if t.live() {
		err = t.admin.AddRelay(*url, k)
	} else {
		err = t.store.AddRelay(*url, k)
	}
	if err != nil {
		return err
	}

	fmt.Printf("added relay %s\n", *url)
	if *pubkey == "" {
		fmt.Print("\nno -key given, so nodes will trust whatever answers at that address.\n")
		fmt.Print("it cannot read their traffic, but it can silently drop it. pin the key with -key.\n")
	}
	return nil
}

func removeRelay(args []string) error {
	af := newAdminFlags("relay rm")
	url := af.fs.String("url", "", "the relay's address")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *url == "" {
		return fmt.Errorf("relay rm needs -url")
	}

	if t.live() {
		err = t.admin.RemoveRelay(*url)
	} else {
		err = t.store.RemoveRelay(*url)
	}
	if err != nil {
		return err
	}
	fmt.Printf("removed relay %s\n", *url)
	return nil
}

func preferRelay(args []string) error {
	af := newAdminFlags("relay prefer")
	url := af.fs.String("url", "", "the relay to make active")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *url == "" {
		return fmt.Errorf("relay prefer needs -url")
	}

	if t.live() {
		err = t.admin.PreferRelay(*url)
	} else {
		err = t.store.PreferRelay(*url)
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s is now the mesh's relay; every node switches on its next netmap\n", *url)
	return nil
}

func listRelays(args []string) error {
	af := newAdminFlags("relay ls")
	t, err := af.open(args)
	if err != nil {
		return err
	}

	var relays []netmap.Relay
	if t.live() {
		relays, err = t.admin.Relays()
	} else {
		relays = t.store.Relays()
	}
	if err != nil {
		return err
	}

	if len(relays) == 0 {
		fmt.Print("no relays registered\n\n")
		fmt.Print("without one, two nodes that cannot already reach each other will not connect.\n")
		fmt.Print("run 'makima-relay serve' somewhere with a public address, then:\n")
		fmt.Print("  makima-server relay add -url <host>:3478 -key <its key>\n")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprint(w, "\tURL\tKEY\n")
	for i, r := range relays {
		marker := " "
		if i == 0 {
			// Only the first is in use; the rest are failover, because two
			// nodes can only meet on a relay they are both connected to.
			marker = "*"
		}
		k := "unpinned"
		if !r.Key.IsZero() {
			k = r.Key.String()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", marker, r.URL, k)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Print("\n* is the active relay. the others are failover, not load spreading.\n")
	return nil
}

// --- routes -------------------------------------------------------------

func routesCmd(args []string) error {
	if len(args) == 0 {
		return listRoutes(nil)
	}
	switch args[0] {
	case "approve":
		return approveRoutes(args[1:])
	case "revoke":
		return revokeRoutes(args[1:])
	case "ls", "list":
		return listRoutes(args[1:])
	default:
		return fmt.Errorf("unknown routes subcommand %q (try: approve, revoke, ls)", args[0])
	}
}

func approveRoutes(args []string) error {
	af := newAdminFlags("routes approve")
	name := af.fs.String("name", "", "the node advertising them")
	routes := af.fs.String("routes", "", "comma-separated prefixes; omit with -all")
	exit := af.fs.Bool("exit", false, "approve this node as an exit node")
	all := af.fs.Bool("all", false, "approve everything the node is advertising")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("routes approve needs -name")
	}
	if *routes == "" && !*exit && !*all {
		return fmt.Errorf("nothing to approve: pass -routes, -exit, or -all")
	}

	prefixes, err := parsePrefixes(*routes)
	if err != nil {
		return err
	}

	if t.live() {
		err = t.admin.ApproveRoutes(*name, prefixes, *exit, *all)
	} else {
		if *all {
			p, e := t.store.Advertised(*name)
			prefixes, *exit = p, e
		}
		err = t.store.ApproveRoutes(*name, prefixes, *exit)
	}
	if err != nil {
		return err
	}
	fmt.Printf("approved; every node installs the routes on its next netmap\n")
	return nil
}

func revokeRoutes(args []string) error {
	af := newAdminFlags("routes revoke")
	name := af.fs.String("name", "", "the node")
	routes := af.fs.String("routes", "", "comma-separated prefixes")
	exit := af.fs.Bool("exit", false, "revoke exit-node approval")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("routes revoke needs -name")
	}

	prefixes, err := parsePrefixes(*routes)
	if err != nil {
		return err
	}

	if t.live() {
		err = t.admin.RevokeRoutes(*name, prefixes, *exit)
	} else {
		err = t.store.RevokeRoutes(*name, prefixes, *exit)
	}
	if err != nil {
		return err
	}
	fmt.Print("revoked\n")
	return nil
}

func listRoutes(args []string) error {
	af := newAdminFlags("routes ls")
	t, err := af.open(args)
	if err != nil {
		return err
	}

	nodes, err := loadNodes(t)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprint(w, "NODE\tADVERTISED\tAPPROVED\tEXIT\n")
	any := false

	for _, n := range nodes {
		if len(n.AdvertisedRoutes) == 0 && !n.AdvertisesExit {
			continue
		}
		any = true

		exit := "—"
		switch {
		case n.AdvertisesExit && n.ExitApproved:
			exit = "approved"
		case n.AdvertisesExit:
			exit = "PENDING"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			n.Name, joinPrefixes(n.AdvertisedRoutes), joinPrefixes(n.ApprovedRoutes), exit)
	}
	if !any {
		fmt.Print("no node is advertising routes\n\n")
		fmt.Print("a node offers to route a subnet with:\n")
		fmt.Print("  sudo makima set -advertise-routes 192.168.1.0/24\n")
		return nil
	}
	return w.Flush()
}

// --- tags and expiry ----------------------------------------------------

func tagsCmd(args []string) error {
	af := newAdminFlags("tags")
	name := af.fs.String("name", "", "the node")
	tags := af.fs.String("tags", "", "comma-separated tags, empty to clear")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("tags needs -name")
	}

	var list []string
	for _, s := range strings.Split(*tags, ",") {
		if s = strings.TrimSpace(s); s != "" {
			list = append(list, s)
		}
	}

	if t.live() {
		err = t.admin.SetTags(*name, list)
	} else {
		err = t.store.SetTags(*name, list)
	}
	if err != nil {
		return err
	}

	if len(list) == 0 {
		fmt.Printf("cleared %s's tags\n", *name)
		return nil
	}
	fmt.Printf("%s is now tagged %s\n", *name, strings.Join(list, ", "))
	return nil
}

func expireCmd(args []string) error {
	af := newAdminFlags("expire")
	name := af.fs.String("name", "", "the node")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("expire needs -name")
	}

	if t.live() {
		err = t.admin.Expire(*name)
	} else {
		err = t.store.ExpireNode(*name)
	}
	if err != nil {
		return err
	}

	fmt.Printf("expired %s; it keeps its address but must present a new auth key to rejoin\n", *name)
	fmt.Print("every other node drops it on its next netmap\n")
	return nil
}

// --- dns ----------------------------------------------------------------

func dnsCmd(args []string) error {
	if len(args) == 0 {
		return dnsStatus(nil)
	}
	switch args[0] {
	case "on":
		return setDNS(args[1:], true)
	case "off":
		return setDNS(args[1:], false)
	case "status":
		return dnsStatus(args[1:])
	default:
		return fmt.Errorf("unknown dns subcommand %q (try: on, off, status)", args[0])
	}
}

func setDNS(args []string, on bool) error {
	af := newAdminFlags("dns")
	domain := af.fs.String("domain", "", "the mesh's DNS suffix (default "+control.DefaultDomain+")")

	t, err := af.open(args)
	if err != nil {
		return err
	}

	if t.live() {
		err = t.admin.SetDNS(on, *domain)
	} else {
		err = t.store.SetDNS(on, *domain)
	}
	if err != nil {
		return err
	}

	if !on {
		fmt.Print("mesh DNS off; nodes remove their resolver entries on the next netmap\n")
		return nil
	}

	d := *domain
	if d == "" {
		d = control.DefaultDomain
	}
	fmt.Printf("mesh DNS on for *.%s\n\n", d)
	fmt.Printf("nodes resolve each other by name: ssh laptop.%s\n", d)
	fmt.Print("only that suffix is routed to the mesh; the machine's other DNS is untouched.\n")
	return nil
}

func dnsStatus(args []string) error {
	af := newAdminFlags("dns status")
	t, err := af.open(args)
	if err != nil {
		return err
	}

	var (
		enabled bool
		domain  string
	)
	if t.live() {
		resp, err := t.admin.DNS()
		if err != nil {
			return err
		}
		enabled, domain = resp.Enabled, resp.Domain
	} else {
		enabled, domain = t.store.DNSSettings()
	}

	if !enabled {
		fmt.Print("mesh DNS is off\n")
		return nil
	}
	fmt.Printf("mesh DNS is on for *.%s\n", domain)
	return nil
}

// --- acl ----------------------------------------------------------------

func aclCmd(args []string) error {
	if len(args) == 0 {
		return showACL(nil)
	}
	switch args[0] {
	case "show":
		return showACL(args[1:])
	case "set":
		return setACL(args[1:])
	case "reset":
		return resetACL(args[1:])
	default:
		return fmt.Errorf("unknown acl subcommand %q (try: show, set, reset)", args[0])
	}
}

func showACL(args []string) error {
	af := newAdminFlags("acl show")
	t, err := af.open(args)
	if err != nil {
		return err
	}

	var p *policy.Policy
	if t.live() {
		p, err = t.admin.Policy()
	} else {
		p = t.store.Policy()
	}
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", b)
	return nil
}

func setACL(args []string) error {
	af := newAdminFlags("acl set")
	file := af.fs.String("file", "", "path to a policy JSON file, or - for stdin")

	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("acl set needs -file (use - for stdin)")
	}

	var raw []byte
	if *file == "-" {
		raw, err = readStdin()
	} else {
		raw, err = os.ReadFile(*file)
	}
	if err != nil {
		return err
	}

	var p policy.Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	// Validated before it is sent, so a typo is caught while the operator is
	// still looking at their editor rather than discovered as an outage.
	if err := p.Validate(); err != nil {
		return err
	}

	if t.live() {
		err = t.admin.SetPolicy(&p)
	} else {
		err = t.store.SetPolicy(&p)
	}
	if err != nil {
		return err
	}

	fmt.Printf("policy set: %d rule(s)\n", len(p.ACLs))
	fmt.Print("every node's netmap and packet filter update on its next poll\n")
	return nil
}

func resetACL(args []string) error {
	af := newAdminFlags("acl reset")
	t, err := af.open(args)
	if err != nil {
		return err
	}

	p := policy.DefaultPolicy()
	if t.live() {
		err = t.admin.SetPolicy(p)
	} else {
		err = t.store.SetPolicy(p)
	}
	if err != nil {
		return err
	}
	fmt.Print("policy reset: every node may reach every other node\n")
	return nil
}

// --- helpers ------------------------------------------------------------

func loadNodes(t *target) ([]control.Node, error) {
	if t.live() {
		return t.admin.Nodes()
	}
	return t.store.Nodes(), nil
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("parse route %q: %w", part, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func joinPrefixes(p []netip.Prefix) string {
	if len(p) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(p))
	for _, x := range p {
		parts = append(parts, x.String())
	}
	return strings.Join(parts, ",")
}

func readStdin() ([]byte, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}
