package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/ddns"
)

// ddnsCmd keeps a free DuckDNS name pointed at this server.
//
// The one step that makes a network held at home reachable from anywhere,
// short of a port forward on the router: a name that follows the home
// connection's address when it changes, handed to every node as a way back
// in when its usual address stops answering.
func ddnsCmd(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return ddnsStatus(args)
	}
	switch args[0] {
	case "set":
		return ddnsSet(args[1:])
	case "off":
		return ddnsOff(args[1:])
	case "status":
		return ddnsStatus(args[1:])
	default:
		return fmt.Errorf("unknown ddns subcommand %q (try: set, off, status)", args[0])
	}
}

func ddnsSet(args []string) error {
	af := newAdminFlags("ddns set")
	rawName := af.fs.String("name", "", "the DuckDNS name, e.g. tenet (for tenet.duckdns.org)")
	token := af.fs.String("token", "", "the token from your DuckDNS page (asked for when omitted)")
	port := af.fs.Int("port", 0, "the port the router forwards to this server (default: the one it listens on)")
	t, err := af.open(args)
	if err != nil {
		return err
	}
	if *rawName == "" {
		if rest := af.fs.Args(); len(rest) > 0 {
			*rawName = rest[0]
		}
	}
	if *rawName == "" {
		return errors.New("ddns set needs -name — the part before .duckdns.org, from https://www.duckdns.org")
	}
	name, err := ddns.Name(*rawName)
	if err != nil {
		return err
	}

	// Asked for rather than required as a flag, so it stays out of shell
	// history and out of the process list.
	if *token == "" {
		if *token, err = askToken(); err != nil {
			return err
		}
	}

	// Checked before anything is stored: a wrong token is the likeliest
	// mistake, and finding out now beats finding out from a laptop in a hotel.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := ddns.Update(ctx, name, *token)
	if errors.Is(err, ddns.ErrRefused) {
		return err
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: could not reach DuckDNS just now (%v); the server will keep trying\n", err)
	}

	var u string
	if t.live() {
		u, err = t.admin.SetDDNS(name, *token, *port)
	} else {
		p := *port
		if p == 0 {
			p = t.port(*af.state)
		}
		u, err = t.store.SetDDNS(control.DDNS{Name: name, Token: *token, Port: p})
	}
	if err != nil {
		return err
	}

	if res.IP != "" {
		fmt.Printf("%s now points at %s, and this server keeps it pointed here.\n", ddns.Host(name), res.IP)
	} else {
		fmt.Printf("%s will point here once DuckDNS answers, and this server keeps it that way.\n", ddns.Host(name))
	}
	fmt.Printf("Every machine on the network learns %s within a minute or so, and uses it\n", u)
	fmt.Println("whenever it cannot reach this server at its usual address.")
	printForwards(u, t.port(*af.state))
	return nil
}

// printForwards says what the router has to let in, since that is the one
// part no program on this machine can do on its own: the port the name is
// reached at from outside, to the port this server actually listens on.
func printForwards(controlURL string, local int) {
	outside := local
	if u, err := url.Parse(controlURL); err == nil {
		switch p := u.Port(); {
		case p != "":
			outside, _ = strconv.Atoi(p)
		case u.Scheme == "https":
			outside = 443
		case u.Scheme == "http":
			outside = 80
		}
	}
	server := strconv.Itoa(local)
	if outside != local {
		server = fmt.Sprintf("%d → %d", outside, local)
	}

	fmt.Println()
	if ip := lanAddr(); ip != "" {
		fmt.Printf("One thing left, on your router: forward these to this machine (%s):\n", ip)
	} else {
		fmt.Println("One thing left, on your router: forward these to this machine:")
	}
	fmt.Printf("  TCP %-11s this server, and the relay that rides on it\n", server)
	if f, err := conf.Load(conf.DefaultPath); err == nil && f.ListenPort != 0 {
		fmt.Printf("  UDP %-11d this machine's tunnel, so the others can connect to it directly\n", f.ListenPort)
	}
	fmt.Println()
	fmt.Println("Without them the name still leads to your house, and the router turns everything away.")
}

func ddnsOff(args []string) error {
	af := newAdminFlags("ddns off")
	t, err := af.open(args)
	if err != nil {
		return err
	}
	if t.live() {
		err = t.admin.ClearDDNS()
	} else {
		err = t.store.ClearDDNS()
	}
	if err != nil {
		return err
	}
	fmt.Println("no longer keeping a DuckDNS name current, or telling nodes about it")
	return nil
}

func ddnsStatus(args []string) error {
	af := newAdminFlags("ddns status")
	t, err := af.open(args)
	if err != nil {
		return err
	}

	var st control.DDNSStatus
	if t.live() {
		if st, err = t.admin.DDNS(); err != nil {
			return err
		}
	} else {
		st = t.store.DDNSState()
	}

	if st.Name == "" {
		fmt.Println("no DuckDNS name set.")
		fmt.Println()
		fmt.Println("to reach this network from anywhere, get a free name at https://www.duckdns.org, then:")
		fmt.Println("  makima-server ddns set -name NAME")
		return nil
	}

	fmt.Printf("%-10s %s\n", "name", st.Name)
	fmt.Printf("%-10s %s\n", "nodes use", st.URL)
	switch {
	case st.Error != "":
		fmt.Printf("%-10s FAILING: %s\n", "status", st.Error)
	case st.IP != "":
		fmt.Printf("%-10s points at %s, checked %s ago\n", "status", st.IP, time.Since(st.Updated).Round(time.Second))
	case !t.live():
		fmt.Printf("%-10s kept current while the server runs; it is not running now\n", "status")
	default:
		fmt.Printf("%-10s not checked yet\n", "status")
	}
	return nil
}

// askToken reads the token without echoing it.
func askToken() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no -token given, and no terminal to ask for it at")
	}
	fmt.Fprint(os.Stderr, "DuckDNS token (from https://www.duckdns.org, shown after you sign in): ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("no token given")
	}
	return tok, nil
}

// lanAddr is this machine's address on its local network — what a router's
// port-forward page asks for.
func lanAddr() string {
	c, err := net.DialTimeout("udp", "1.1.1.1:53", 2*time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return ""
	}
	return host
}
