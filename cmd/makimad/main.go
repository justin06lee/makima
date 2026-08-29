// Command makimad is the node daemon: it brings up the tunnel and keeps it
// matching the netmap.
//
// In static mode the netmap comes from the config file and never changes, and
// WireGuard gets an ordinary UDP socket — a hand-maintained mesh has no
// control plane to tell it about relays, and nothing to discover.
//
// In managed mode the netmap comes from the control server over a long poll,
// and WireGuard gets magicsock instead: a socket that decides per packet
// whether a peer is reachable directly or has to go through the relay, and
// switches between them without WireGuard noticing. Every netmap update is
// applied to the running device in place, so flows survive peers, paths and
// policies changing underneath them.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/dnsserver"
	"github.com/justin06lee/makima/internal/magicsock"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/policy"
	"github.com/justin06lee/makima/internal/portmap"
	"github.com/justin06lee/makima/internal/stun"
	"github.com/justin06lee/makima/internal/wg"
)

var version = "dev"

func main() {
	log.SetFlags(0)
	log.SetPrefix("makimad: ")

	configPath := flag.String("config", conf.DefaultPath, "path to node configuration")
	ifaceName := flag.String("iface", defaultIface, "TUN interface name")
	mtu := flag.Int("mtu", wg.DefaultMTU, "tunnel MTU")
	verbose := flag.Bool("v", false, "log WireGuard handshakes and peer state")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	if err := run(*configPath, *ifaceName, *mtu, *verbose); err != nil {
		log.Fatal(err)
	}
}

// node is everything the daemon holds together for the life of the tunnel.
type node struct {
	cfgPath string
	file    *conf.File

	engine     *wg.Engine
	router     *netcfg.Router
	sock       *magicsock.Conn
	client     *control.Client
	dns        *dnsserver.Server
	resolver   *netcfg.Resolver
	advertiser *netcfg.Advertiser
	exitClient *netcfg.ExitClient
	pm         *portmap.Client

	// filter is the compiled policy currently being enforced. Stored on the
	// node rather than inside the tunnel wrapper so a netmap update can swap
	// it atomically without disturbing the data path.
	filter *policy.Guard

	verbose bool
}

func run(configPath, ifaceName string, mtu int, verbose bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root to create a TUN device (try: sudo %s)", os.Args[0])
	}

	f, err := conf.Load(configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	n := &node{cfgPath: configPath, file: f, verbose: verbose, filter: policy.NewGuard()}

	// A managed node gets the path-selecting socket; a static one gets an
	// ordinary UDP socket. The split matters: magicsock attributes an inbound
	// packet to a peer by address or by relay header, and a static mesh has no
	// disco keys to establish either, so it would break the documented
	// "whichever machine speaks first teaches the other" behaviour.
	var wgOpts wg.Options
	wgOpts.MTU = mtu
	wgOpts.Verbose = verbose
	wgOpts.Filter = n.filter.AllowInbound

	if f.Managed() {
		sock, err := magicsock.New(magicsock.Options{
			Port:     f.ListenPort,
			NodeKey:  f.NodeKey,
			DiscoKey: f.DiscoKey,
			Logger:   log.Default(),
		})
		if err != nil {
			return err
		}
		defer sock.Close()

		n.sock = sock
		wgOpts.Bind = sock
		wgOpts.Endpoint = magicsock.EndpointString

		// The socket may have been given port 0 and picked its own; everything
		// downstream advertises whatever it actually got.
		f.ListenPort = sock.LocalPort()

		n.pm = portmap.New(log.Default())
		n.client = control.NewClient(f.LoginServer, f.ServerKey, f.MachineKey)

		if err := n.register(ctx); err != nil {
			if len(f.Self.Addresses) == 0 {
				return fmt.Errorf("%w (and no cached netmap to fall back on)", err)
			}
			// A cached netmap is enough to come up. The mesh as of last contact
			// is far better than no mesh at all, and the poll loop reconciles
			// once the server returns.
			log.Printf("warning: %v", err)
			log.Print("starting from the last known netmap; will keep retrying")
		}
	}

	addr, err := f.Self.Addr()
	if err != nil {
		return err
	}

	m := n.netMap()

	engine, err := wg.Up(ifaceName, m.WireGuardConfig(), wgOpts)
	if err != nil {
		return err
	}
	defer engine.Close()
	n.engine = engine

	n.router = netcfg.NewRouter(engine.Name())
	if err := n.router.SetAddr(addr); err != nil {
		return err
	}
	if err := n.router.Sync(m.Routes()); err != nil {
		log.Printf("warning: %v", err)
	}
	defer n.router.Close()

	if n.sock != nil {
		n.applyNetwork(m)
	}
	n.logState(engine.Name())

	if n.client != nil {
		go n.poll(ctx)
		go n.gatherEndpoints(ctx)
	}

	down := make(chan struct{})
	go func() { engine.Wait(); close(down) }()

	select {
	case <-ctx.Done():
		log.Print("shutting down")
	case <-down:
		log.Print("device went down")
	}

	// Tear the host configuration back down explicitly. Routes and resolver
	// settings outlive the process that made them, and a node that leaves them
	// behind blackholes mesh addresses until the next reboot.
	n.shutdown()
	return nil
}

// netMap renders the current configuration into the mesh view.
func (n *node) netMap() *netmap.NetMap {
	m := n.file.NetMap()
	if n.sock != nil {
		m.ListenPort = n.sock.LocalPort()
	}
	return m
}

// register introduces this node to the control server and records what it was
// given back.
func (n *node) register(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := n.client.Register(ctx, &control.RegisterRequest{
		Name:            n.file.Self.Name,
		NodeKey:         n.file.NodeKey.Public(),
		DiscoKey:        n.file.DiscoKey.Public(),
		AuthKey:         n.file.AuthKey,
		Endpoints:       n.endpoints(),
		AdvertiseRoutes: n.file.AdvertiseRoutes,
		AdvertiseExit:   n.file.AdvertiseExit,
	})
	if err != nil {
		return err
	}

	n.file.Self.ID = resp.NodeID
	n.file.Self.Key = n.file.NodeKey.Public()
	n.file.Self.DiscoKey = n.file.DiscoKey.Public()
	n.file.Self.Addresses = []netip.Prefix{resp.Address}

	// The auth key has now been redeemed. Keeping it would leave a reusable
	// credential sitting in a file on every machine that ever joined.
	if n.file.AuthKey != "" {
		n.file.AuthKey = ""
		if err := conf.Save(n.cfgPath, n.file); err != nil {
			log.Printf("warning: could not clear the stored auth key: %v", err)
		}
	}

	if len(resp.PendingRoutes) > 0 || resp.PendingExit {
		log.Printf("waiting for approval of %s", describePending(resp.PendingRoutes, resp.PendingExit))
		log.Printf("approve with: makima-server routes approve -name %s", n.file.Self.Name)
	}
	return nil
}

// endpoints is everything this node currently believes peers could reach it at.
//
// The union of three sources, each blind in a way the others are not: local
// interface addresses (right on a LAN, useless behind NAT), addresses observed
// by peers and STUN servers (right on the internet, absent until something
// answers), and a port mapping this node asked its router for (right when the
// router cooperates).
func (n *node) endpoints() []netip.AddrPort {
	port := n.file.ListenPort
	if n.sock != nil {
		port = n.sock.LocalPort()
	}

	out := netcfg.LocalEndpoints(port)
	if n.sock != nil {
		for _, e := range n.sock.SelfEndpoints() {
			out = appendUniqueAddrPort(out, e)
		}
	}
	if n.pm != nil {
		if e, ok := n.pm.External(); ok {
			out = appendUniqueAddrPort(out, e)
		}
	}
	return out
}

// poll keeps the local netmap in step with the control server.
func (n *node) poll(ctx context.Context) {
	var version uint64
	backoff := time.Second

	for ctx.Err() == nil {
		// Re-read on every poll rather than once at startup: a laptop that
		// moves between networks gets a new address, and a peer holding the
		// old one has no way to notice it went stale.
		resp, err := n.client.PollMap(ctx, version, n.endpoints())
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("netmap poll failed: %v (retrying in %s)", err, backoff)

			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			// Capped: a control server down for an hour should not mean an
			// hour's delay noticing it came back.
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second

		if resp.Version == version {
			continue // heartbeat, nothing moved
		}
		version = resp.Version

		n.apply(ctx, resp)
	}
}

// apply installs a new netmap.
func (n *node) apply(ctx context.Context, resp *control.MapResponse) {
	// Verify peer key signatures before anything else touches them. This is
	// the whole point of the network lock: a control server that invents a
	// peer has to forge a signature it holds no key for, and the invention is
	// dropped here rather than admitted to the data plane.
	peers, rejected := verifyPeers(resp)
	if len(rejected) > 0 {
		for _, r := range rejected {
			log.Printf("REFUSING peer %s: %v", r.name, r.err)
		}
	}

	n.file.Self = resp.Self
	n.file.Peers = peers
	n.file.Domain = resp.Domain
	n.file.HomeRelay = resp.HomeRelay

	m := n.netMap()
	m.HomeRelay = resp.HomeRelay
	m.Domain = resp.Domain
	m.DNS = resp.DNS

	if err := n.engine.SetConfig(m.WireGuardConfig()); err != nil {
		log.Printf("apply netmap: %v", err)
		return
	}
	if n.sock != nil {
		n.applyNetwork(m)
	}

	n.filter.Set(resp.Filter)

	if err := n.router.Sync(m.Routes()); err != nil {
		log.Printf("warning: %v", err)
	}
	n.applyExitNode(m)
	n.applyDNS(ctx, m)

	// Persist last, so a cache is only written for a netmap that was actually
	// applied successfully.
	if err := conf.Save(n.cfgPath, n.file); err != nil {
		log.Printf("cache netmap: %v", err)
	}

	log.Printf("netmap v%d: %d peer(s)%s", resp.Version, len(peers), relaySuffix(resp.HomeRelay))
	for _, p := range peers {
		logPeer(p)
	}
}

// applyNetwork hands the socket its view of who is reachable how.
func (n *node) applyNetwork(m *netmap.NetMap) {
	peers := make([]magicsock.PeerConfig, 0, len(m.Peers))
	for _, p := range m.Peers {
		peers = append(peers, magicsock.PeerConfig{
			NodeKey:   p.Key,
			DiscoKey:  p.DiscoKey,
			Endpoints: p.Endpoints,
			RelayURL:  p.RelayURL,
		})
	}
	n.sock.SetNetwork(peers, m.HomeRelay.URL, m.HomeRelay.Key)
}

// gatherEndpoints keeps this node's own reachability up to date.
//
// Two independent probes on the same timer. STUN asks a public server what
// address our packets appear to come from, which works behind almost any NAT
// but tells us nothing about whether an inbound packet would get back. A port
// mapping asks the router to make one specifically get back, which is far
// better when it works and unavailable when it does not. Doing both and
// advertising the union means a peer has something to try in either case.
func (n *node) gatherEndpoints(ctx context.Context) {
	// Immediately, then on a slow timer: the first sweep is what makes a node
	// reachable at all, and everything after it is maintenance.
	n.refreshEndpoints(ctx)

	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.refreshEndpoints(ctx)
		}
	}
}

func (n *node) refreshEndpoints(ctx context.Context) {
	// STUN answers arrive on the shared socket's normal receive path, so this
	// only sends. There is nothing to wait for here — the observation lands
	// asynchronously and the next poll advertises it.
	if err := n.sock.QuerySTUN(ctx, stun.DefaultServers); err != nil && n.verbose {
		log.Printf("stun: %v", err)
	}

	if n.pm != nil {
		if addr, err := n.pm.Map(ctx, n.sock.LocalPort()); err == nil {
			n.sock.NoteSelfObservation(addr)
		} else if n.verbose {
			log.Printf("portmap: %v", err)
		}
	}
}

func (n *node) shutdown() {
	if n.dns != nil {
		n.dns.Close()
	}
	if n.pm != nil {
		n.pm.Close()
	}
	if n.router != nil {
		n.router.Close()
	}
}

func (n *node) logState(iface string) {
	addr, _ := n.file.Self.Addr()
	mode := "static"
	if n.file.Managed() {
		mode = n.file.LoginServer
	}
	log.Printf("%s up on %s as %s [%s], %d peer(s)", iface, addr, n.file.Self.Name, mode, len(n.file.Peers))
	for _, p := range n.file.Peers {
		logPeer(p)
	}
}

func logPeer(p netmap.Node) {
	via := "no known path"
	switch {
	case len(p.Endpoints) > 0:
		via = p.Endpoints[0].String()
	case p.RelayURL != "":
		via = "relay " + p.RelayURL
	}
	a, _ := p.Addr()
	log.Printf("  peer %-16s %-15s via %s", p.Name, a, via)
}

func relaySuffix(r netmap.Relay) string {
	if r.URL == "" {
		return ""
	}
	return ", relay " + r.URL
}

func describePending(routes []netip.Prefix, exit bool) string {
	var parts []string
	for _, r := range routes {
		parts = append(parts, r.String())
	}
	if exit {
		parts = append(parts, "exit node")
	}
	return strings.Join(parts, ", ")
}

func appendUniqueAddrPort(s []netip.AddrPort, a netip.AddrPort) []netip.AddrPort {
	for _, x := range s {
		if x == a {
			return s
		}
	}
	return append(s, a)
}
