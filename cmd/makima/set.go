package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/netmap"
)

// `set` changes what this node asks the mesh for, and `status` shows what it
// got. They are separate because the two are genuinely different questions:
// what a node advertises is local and takes effect immediately, while whether
// anyone acts on it is an operator's decision on the control server.

func set(args []string) error {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	routes := fs.String("advertise-routes", "", "comma-separated subnets to route for the mesh, or \"\" to stop")
	exitNode := fs.String("exit-node", "", "route this machine's traffic through the named peer, or \"\" to stop")
	advertiseExit := fs.String("advertise-exit-node", "", "offer to be an exit node: true or false")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// A flag that was not passed must not overwrite what is already set, and
	// flag.Bool cannot express "unset" — hence the string for the boolean.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if len(set) == 0 {
		return fmt.Errorf("set needs something to set (try -advertise-routes, -exit-node, or -advertise-exit-node)")
	}

	f, err := conf.Load(*path)
	if err != nil {
		return err
	}
	if !f.Managed() {
		return fmt.Errorf("this node is not managed by a control server; subnet routes and exit nodes need one")
	}

	var changed []string

	if set["advertise-routes"] {
		prefixes, err := parseRoutes(*routes)
		if err != nil {
			return err
		}
		f.AdvertiseRoutes = prefixes
		if len(prefixes) == 0 {
			changed = append(changed, "stopped advertising routes")
		} else {
			changed = append(changed, "advertising "+*routes)
		}
	}

	if set["advertise-exit-node"] {
		switch strings.ToLower(*advertiseExit) {
		case "true", "yes", "on", "1":
			f.AdvertiseExit = true
			changed = append(changed, "offering to be an exit node")
		case "false", "no", "off", "0":
			f.AdvertiseExit = false
			changed = append(changed, "no longer offering to be an exit node")
		default:
			return fmt.Errorf("-advertise-exit-node takes true or false, got %q", *advertiseExit)
		}
	}

	if set["exit-node"] {
		f.ExitNode = *exitNode
		if *exitNode == "" {
			changed = append(changed, "no longer using an exit node")
		} else {
			changed = append(changed, "routing through "+*exitNode)
		}
	}

	if err := conf.Save(*path, f); err != nil {
		return err
	}

	for _, c := range changed {
		fmt.Printf("%s\n", c)
	}

	// The daemon reads this file at startup and republishes on registration, so
	// a change made while it is running needs it restarted. Saying so is worth
	// more than silently leaving the operator to wonder.
	fmt.Print("\nrestart the daemon for this to take effect: sudo pkill makimad && sudo makimad\n")
	if f.AdvertiseExit || len(f.AdvertiseRoutes) > 0 {
		fmt.Print("then approve it on the control server:\n")
		fmt.Printf("  makima-server routes approve -name %s -all\n", f.Self.Name)
	}
	return nil
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	f, err := conf.Load(*path)
	if err != nil {
		return err
	}

	selfAddr, _ := f.Self.Addr()
	fmt.Printf("%-10s %s (%s)\n", "node", f.Self.Name, selfAddr)

	switch {
	case f.Managed():
		fmt.Printf("%-10s %s\n", "server", f.LoginServer)
	case f.Serverless:
		fmt.Printf("%-10s none (paired directly)\n", "server")
	default:
		fmt.Printf("%-10s none (static mesh)\n", "server")
	}

	if f.HomeRelay.URL != "" {
		fmt.Printf("%-10s %s\n", "relay", f.HomeRelay.URL)
	}
	if f.Domain != "" {
		fmt.Printf("%-10s *.%s\n", "names", f.Domain)
	}
	if len(f.AdvertiseRoutes) > 0 {
		fmt.Printf("%-10s %s\n", "routing", joinPrefixes(f.AdvertiseRoutes))
	}
	if f.AdvertiseExit {
		fmt.Printf("%-10s offering\n", "exit node")
	}
	if f.ExitNode != "" {
		fmt.Printf("%-10s via %s\n", "traffic", f.ExitNode)
	}

	// Read from the daemon rather than the file, because the default inbox is
	// resolved at runtime from whoever started it — the file usually says
	// nothing at all, and printing that would be misleading.
	if c, err := dialDaemon(*path); err == nil {
		if st, err := c.Status(); err == nil {
			switch {
			case st.Inbox.Active && st.Inbox.Received > 0:
				fmt.Printf("%-10s %s (%d received)\n", "inbox", st.Inbox.Dir, st.Inbox.Received)
			case st.Inbox.Active:
				fmt.Printf("%-10s %s\n", "inbox", st.Inbox.Dir)
			default:
				fmt.Printf("%-10s off\n", "inbox")
			}
		}
	}

	if len(f.Peers) == 0 {
		fmt.Print("\nno peers\n")
		return nil
	}

	fmt.Printf("\n%d peer(s):\n", len(f.Peers))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprint(w, "  NAME\tADDRESS\tPATHS\tOFFERS\n")

	for _, p := range f.Peers {
		a, _ := p.Addr()

		paths := "relay only"
		if len(p.Endpoints) > 0 {
			var eps []string
			for _, e := range p.Endpoints {
				eps = append(eps, e.String())
			}
			paths = strings.Join(eps, " ")
		}

		var offers []string
		if p.OffersExit() {
			offers = append(offers, "exit")
		}
		for _, r := range p.AllowedIPs {
			if !netmap.IsDefaultHalf(r) {
				offers = append(offers, r.String())
			}
		}
		offer := "—"
		if len(offers) > 0 {
			offer = strings.Join(offers, ",")
		}

		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", p.Name, a, paths, offer)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// The netmap's endpoint list is what peers *advertise*, not what this node
	// is actually using — that is decided per packet inside the daemon and
	// changes as paths come and go. Saying so prevents the table above from
	// being read as a claim it does not make.
	fmt.Print("\npaths are what each peer advertises. the daemon picks between them,\n")
	fmt.Print("and falls back to the relay when none of them answers.\n")
	return nil
}

func parseRoutes(s string) ([]netip.Prefix, error) {
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
		// Masked, because 192.168.1.5/24 is almost always a typo for
		// 192.168.1.0/24, and silently advertising the former produces a route
		// that behaves subtly differently from the one that was meant.
		if p != p.Masked() {
			return nil, fmt.Errorf("%s has host bits set; did you mean %s?", p, p.Masked())
		}
		out = append(out, p)
	}
	return out, nil
}

func joinPrefixes(p []netip.Prefix) string {
	parts := make([]string, 0, len(p))
	for _, x := range p {
		parts = append(parts, x.String())
	}
	return strings.Join(parts, ",")
}
