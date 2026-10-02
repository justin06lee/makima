package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/ddns"
	"github.com/justin06lee/makima/internal/hostaddr"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/portmap"
)

// `makima duck`: reaching this network from anywhere, step by step, from
// wherever it stands now.
//
// makima-server ddns does the work, but it is the third of five steps, and the
// other four happen in a browser and on a router where no program of ours can
// go. So this walks all five, says which machine each happens on, and marks
// what is already done — running it again is how somebody finds out what is
// left. It only reads, and needs no root.

// duckPlan is everything the walk-through says, worked out before any of it is
// printed.
type duckPlan struct {
	// Server is the machine holding the network, by name where it can be
	// told, and Here says it is this one.
	Server string
	Here   bool

	// Addr is the server's address as the machines here reach it, and Port
	// the TCP port it listens on; Private says Addr only works indoors.
	Addr    netip.Addr
	Port    int
	Private bool

	// TunnelPort is the server machine's own WireGuard port.
	TunnelPort int

	// Router is the router's address, when this machine shares a network
	// with the server and so the router too.
	Router netip.Addr

	// Duck is the DuckDNS name the server already keeps, empty until step 3
	// is done; DuckIP is where it points now, and Answers whether the server
	// answered at the name from here.
	Duck    string
	DuckIP  string
	Answers bool
}

func duckCmd(args []string) error {
	fs := flag.NewFlagSet("duck", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := dialDaemon(*path)
	if errors.Is(err, localapi.ErrNoDaemon) {
		fmt.Println("makima is not running here, so there is no network to reach yet — start one with: makima up")
		fmt.Println("Run makima duck again afterwards, on any machine in it.")
		return nil
	}
	if err != nil {
		return err
	}
	st, err := c.Status()
	if err != nil {
		return err
	}

	switch {
	case st.Serverless:
		fmt.Println("This machine was paired (makima pair), so its network has no server for a name")
		fmt.Println("to lead to: the relay is what finds machines that have moved. DuckDNS is for a")
		fmt.Println("network started with makima up.")
		return nil
	case !st.Managed || st.Server == "":
		fmt.Println("This machine's network is kept by hand (makima init), so there is no server for")
		fmt.Println("a name to lead to. DuckDNS is for a network started with makima up.")
		return nil
	}

	p, err := planDuck(st, hostaddr.NetworkAddrs())
	if err != nil {
		return err
	}
	p.look(*path)
	p.write(os.Stdout)
	return nil
}

// planDuck works out the walk-through from status alone, and the addresses
// this machine holds — enough to test without a network.
func planDuck(st localapi.Status, local []netip.Addr) (duckPlan, error) {
	u, err := url.Parse(st.Server)
	if err != nil || u.Hostname() == "" {
		return duckPlan{}, fmt.Errorf("cannot read the server's address %q", st.Server)
	}

	p := duckPlan{Port: urlPort(u), TunnelPort: 51820}

	for _, raw := range append([]string{st.Server}, st.ServerURLs...) {
		if d, err := url.Parse(raw); err == nil && strings.HasSuffix(d.Hostname(), ddns.Suffix) {
			p.Duck = d.Hostname()
			break
		}
	}

	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		p.Addr = a.Unmap()
	}
	if p.Addr.IsValid() {
		p.Private = p.Addr.IsPrivate() || p.Addr.IsLoopback() || p.Addr.IsLinkLocalUnicast() || cgnat.Contains(p.Addr)
		p.Here = p.Addr.IsLoopback()
		for _, a := range local {
			if a == p.Addr {
				p.Here = true
			}
		}
	}

	if p.Here {
		p.Server = st.Node.Name
		return p, nil
	}
	// The server's machine is the peer reached directly at the server's
	// address. Its port on that path is the tunnel's, which is the one the
	// router has to forward.
	for _, peer := range st.Peers {
		ap, err := netip.ParseAddrPort(strings.TrimPrefix(peer.Path, "direct "))
		if err == nil && p.Addr.IsValid() && ap.Addr().Unmap() == p.Addr {
			p.Server = peer.Name
			p.TunnelPort = int(ap.Port())
			break
		}
	}
	return p, nil
}

// cgnat is the carrier-grade NAT range: an address in it is no more reachable
// from outside than a private one.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// urlPort is the port a URL reaches, written or implied.
func urlPort(u *url.URL) int {
	if p, err := strconv.Atoi(u.Port()); err == nil {
		return p
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

// look fills in what has to be asked of the network: where the name points,
// whether the server answers at it, and where the router is.
func (p *duckPlan) look(path string) {
	if p.Here {
		if f, err := conf.Load(path); err == nil && f.ListenPort != 0 {
			p.TunnelPort = int(f.ListenPort)
		}
	}

	if gw, err := portmap.Gateway(); err == nil && p.Private && sameNetwork(gw, p.Addr) {
		p.Router = gw
	}

	if p.Duck == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if ips, err := net.DefaultResolver.LookupHost(ctx, p.Duck); err == nil && len(ips) > 0 {
		p.DuckIP = ips[0]
	}
	if conn, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", net.JoinHostPort(p.Duck, strconv.Itoa(p.Port))); err == nil {
		conn.Close()
		p.Answers = true
	}
}

// sameNetwork says two IPv4 addresses are on one /24, which is what a home
// network almost always is.
func sameNetwork(a, b netip.Addr) bool {
	if !a.Is4() || !b.Is4() {
		return false
	}
	pa, _ := a.Prefix(24)
	return pa.Contains(b)
}

func (p duckPlan) write(w io.Writer) {
	on := "on " + p.Server
	server := p.Server
	if p.Here {
		on, server = "here", "this machine"
	} else if p.Server == "" {
		on, server = "on the machine running the server", "the server's machine"
	}
	addr := "its address"
	if p.Addr.IsValid() {
		addr = p.Addr.String()
	}

	fmt.Fprintln(w, "makima duck — reach your network from anywhere")
	fmt.Fprintln(w)

	switch {
	case p.Duck != "":
		fmt.Fprintf(w, "Machines that leave home find the server at %s.\n", p.Duck)
	case p.Private:
		fmt.Fprintf(w, "Right now the server is %s, at %s:%d: a private address,\n", server, addr, p.Port)
		fmt.Fprintln(w, "which only works inside this building. Every machine here reaches it; one")
		fmt.Fprintln(w, "that leaves (a laptop at a café) loses track of the others until it is back.")
		fmt.Fprintln(w, "A free DuckDNS name and two lines on your router fix that.")
	default:
		fmt.Fprintf(w, "Right now the server is %s, at %s:%d: a public address,\n", server, addr, p.Port)
		fmt.Fprintln(w, "which works from anywhere until your connection's address changes, as home")
		fmt.Fprintln(w, "ones do now and then. A free DuckDNS name follows it when it does.")
	}
	fmt.Fprintln(w)

	if p.Duck != "" {
		fmt.Fprintf(w, "  ✓ 1–3. the server keeps %s pointed at your home,\n", p.Duck)
		if p.DuckIP != "" {
			fmt.Fprintf(w, "         now %s, ", p.DuckIP)
		} else {
			fmt.Fprint(w, "         ")
		}
		fmt.Fprintln(w, "and every machine knows to look for it there.")
		fmt.Fprintf(w, "         another name: sudo makima-server ddns set -name NEW, %s\n", on)
	} else {
		fmt.Fprintln(w, "  1. Get a name")
		fmt.Fprintln(w, "       open https://www.duckdns.org and sign in (GitHub, Google, Reddit or X).")
		fmt.Fprintln(w, "       type any free name under \"sub domain\" and press \"add domain\": that")
		fmt.Fprintln(w, "       name, NAME.duckdns.org, is now yours. Any machine with a browser will do.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  2. Copy your token")
		fmt.Fprintln(w, "       it is at the top of the same page, beside \"token\". It is the only key")
		fmt.Fprintln(w, "       to your name: keep it out of chats and screenshots.")
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  3. Give both to the server, %s:\n", on)
		if !p.Here && p.Server != "" {
			fmt.Fprintf(w, "       makima possess %s                (or sit at it)\n", p.Server)
		}
		fmt.Fprintln(w, "       sudo makima-server ddns set -name NAME")
		fmt.Fprintln(w, "     and paste the token when asked — it is not shown, and stays out of your")
		fmt.Fprintln(w, "     shell history. The server checks it with DuckDNS at once, keeps the name")
		fmt.Fprintln(w, "     pointed at your home from then on, and every machine learns it within a")
		fmt.Fprintln(w, "     minute.")
	}
	fmt.Fprintln(w)

	target := addr
	if p.Router.IsValid() {
		fmt.Fprintf(w, "  4. Let the traffic in, on your router (most likely http://%s):\n", p.Router)
	} else {
		fmt.Fprintln(w, "  4. Let the traffic in, on the router of the building the server is in:")
	}
	fmt.Fprintln(w, "       under \"port forwarding\" (or \"NAT\", or \"virtual server\"), add")
	fmt.Fprintf(w, "         TCP %-6d → %-16s the server, and the relay that rides on it\n", p.Port, target)
	fmt.Fprintf(w, "         UDP %-6d → %-16s %s tunnel, so machines connect directly\n", p.TunnelPort, target, possessive(server))
	fmt.Fprintln(w, "       without them the name leads to your house, and the router turns")
	fmt.Fprintln(w, "       everybody away.")
	if p.Duck != "" {
		if p.Answers {
			fmt.Fprintf(w, "       ✓ the server answers at %s:%d from here, so the TCP one works.\n", p.Duck, p.Port)
		} else {
			fmt.Fprintf(w, "       from here, the server does not answer at %s:%d —\n", p.Duck, p.Port)
			fmt.Fprintln(w, "       which proves nothing from inside your own network, since many")
			fmt.Fprintln(w, "       routers never loop back to themselves. Step 5 is the real test.")
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  5. Check it")
	fmt.Fprintf(w, "       sudo makima-server ddns status    %s: \"points at\" your home's address\n", on)
	fmt.Fprintln(w, "     then from outside — a phone's hotspot will do — run makima status: the")
	fmt.Fprintln(w, "     other machines should be there.")
	if p.Duck == "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "makima duck again, on any machine, shows what is done and what is left.")
	}
}

// possessive is "tenet's", or "its" for a machine that has no name here.
func possessive(name string) string {
	switch name {
	case "this machine":
		return "this machine's"
	case "the server's machine":
		return "its"
	}
	return name + "'s"
}
