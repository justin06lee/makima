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
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/dnsserver"
	"github.com/justin06lee/makima/internal/drop"
	"github.com/justin06lee/makima/internal/magicsock"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/policy"
	"github.com/justin06lee/makima/internal/portmap"
	"github.com/justin06lee/makima/internal/serve"
	"github.com/justin06lee/makima/internal/sshd"
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
	uiAddr := flag.String("ui", "", "serve the web UI on this address, e.g. 127.0.0.1:8088")
	uiWrite := flag.Bool("ui-write", false, "let the web UI change settings, not just show them")
	noFirewall := flag.Bool("no-firewall", false, "do not touch the host firewall")
	noAutoServe := flag.Bool("no-auto-serve", false, "do not publish this machine's loopback services on the mesh automatically")
	noRecv := flag.Bool("no-recv", false, "do not accept files from peers")
	inbox := flag.String("inbox", "", "where files sent by peers land (default: the invoking user's Downloads/makima)")
	maxFile := flag.Int64("max-file", drop.DefaultMaxSize, "largest file to accept, in bytes")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	opts := options{
		configPath:  *configPath,
		iface:       *ifaceName,
		mtu:         *mtu,
		verbose:     *verbose,
		uiAddr:      *uiAddr,
		uiWrite:     *uiWrite,
		noFirewall:  *noFirewall,
		noAutoServe: *noAutoServe,
		noRecv:      *noRecv,
		inbox:       *inbox,
		maxFile:     *maxFile,
	}
	if err := run(opts); err != nil {
		log.Fatal(err)
	}
}

// node is everything the daemon holds together for the life of the tunnel.
type node struct {
	cfgPath   string
	ifaceName string
	startedAt time.Time

	// mu guards file. The poll loop rewrites it on every netmap while the
	// local API reads it on every status request and writes it when somebody
	// publishes a port, so this is genuinely contended rather than defensive.
	mu   sync.Mutex
	file *conf.File

	// lastPoll and lastPollErr are what the doctor reports about the control
	// plane. Guarded by mu with the rest.
	lastPoll    time.Time
	lastPollErr error

	engine     *wg.Engine
	router     *netcfg.Router
	sock       *magicsock.Conn
	client     *control.Client
	dns        *dnsserver.Server
	resolver   *netcfg.Resolver
	advertiser *netcfg.Advertiser
	exitClient *netcfg.ExitClient
	pm         *portmap.Client
	serve      *serve.Manager
	firewall   *netcfg.Firewall
	inbox      *drop.Receiver
	ssh        *sshd.Server
	sshKeys    *sshd.Keys

	// opts is the command line as given, kept so settings that can change at
	// runtime can be re-resolved against the flags that still override them.
	opts options

	// autoServices are the loopback ports the daemon found and published by
	// itself, kept apart from file.Services so a scan never rewrites the
	// operator's own configuration. Guarded by mu.
	autoServices []serve.Service

	// autoServe is whether to look for them at all, and uiPort is the one
	// loopback port that must never be republished onto the mesh.
	autoServe bool
	uiPort    uint16

	// filter is the compiled policy currently being enforced. Stored on the
	// node rather than inside the tunnel wrapper so a netmap update can swap
	// it atomically without disturbing the data path.
	filter *policy.Guard

	verbose bool
}

// options are the daemon's command-line settings, gathered so run's signature
// does not grow a parameter per flag.
type options struct {
	configPath  string
	iface       string
	mtu         int
	verbose     bool
	uiAddr      string
	uiWrite     bool
	noFirewall  bool
	noAutoServe bool

	// noRecv, inbox and maxFile configure the file receiver. Kept here rather
	// than resolved at startup because the stored settings can change while
	// the daemon runs, and the flags have to keep winning when they do.
	noRecv  bool
	inbox   string
	maxFile int64
}

func run(opts options) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root to create a TUN device (try: sudo %s)", os.Args[0])
	}

	configPath, ifaceName, mtu, verbose := opts.configPath, opts.iface, opts.mtu, opts.verbose

	f, err := conf.Load(configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	n := &node{
		cfgPath:   configPath,
		ifaceName: ifaceName,
		startedAt: time.Now(),
		file:      f,
		verbose:   verbose,
		filter:    policy.NewGuard(),
		serve:     serve.New(log.Default()),
		autoServe: !opts.noAutoServe,
		uiPort:    uiPort(opts.uiAddr),
		inbox:     drop.New(log.Default()),
		ssh:       sshd.New(log.Default()),
		sshKeys:   sshd.NewKeys(log.Default()),
		opts:      opts,
	}
	defer n.serve.Close()
	defer n.inbox.Close()
	defer n.ssh.Close()
	defer n.sshKeys.Close()

	// A managed node gets the path-selecting socket; a static one gets an
	// ordinary UDP socket. The split matters: magicsock attributes an inbound
	// packet to a peer by address or by relay header, and a static mesh has no
	// disco keys to establish either, so it would break the documented
	// "whichever machine speaks first teaches the other" behaviour.
	var wgOpts wg.Options
	wgOpts.MTU = mtu
	wgOpts.Verbose = verbose
	wgOpts.Filter = n.filter.AllowInbound

	if f.NeedsPathSelection() {
		sock, err := magicsock.New(magicsock.Options{
			Port:     f.ListenPort,
			NodeKey:  f.NodeKey,
			DiscoKey: f.DiscoKey,
			Logger:   log.Default(),
		})
		if err != nil {
			return err
		}
		defer sock.Shutdown()

		n.sock = sock
		wgOpts.Bind = sock
		wgOpts.Endpoint = magicsock.EndpointString

		// The socket may have been given port 0 and picked its own; everything
		// downstream advertises whatever it actually got.
		f.ListenPort = sock.LocalPort()

		n.pm = portmap.New(log.Default())
	}

	if f.Managed() {
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

	// The host firewall is configured after the interface exists, because
	// every backend identifies the rule by interface name and the name is not
	// known until the kernel has assigned one.
	n.firewall = netcfg.NewFirewall(engine.Name())
	if !opts.noFirewall {
		n.openFirewall()
	}
	defer n.firewall.Reset()

	// Services can start as soon as there is an address to bind to. A managed
	// node that has one cached comes up serving immediately rather than after
	// its first poll.
	n.serve.Apply(addr, f.Services)

	// The inbox and the SSH server both bind the mesh address, so they can
	// start as soon as there is one — the same moment published ports can.
	n.applyInbox()
	n.applySSH(ctx)

	if n.autoServe {
		log.Print("auto-serve: on — services on 127.0.0.1 are published to your mesh as they appear")
		log.Print("           your mesh is trusted like this machine is; -no-auto-serve turns it off")
		go n.watchLocalPorts(ctx)
	}

	stopAPI, err := n.serveLocalAPI(ctx, opts)
	if err != nil {
		return err
	}
	defer stopAPI()

	n.logState(engine.Name())

	if n.client != nil {
		go n.poll(ctx)
	}
	// Endpoint gathering belongs to the socket, not the control plane. A
	// serverless node needs its own reachable addresses just as much — they
	// are what a pairing address is mostly made of, and without them two
	// machines on the same LAN would have to meet at a relay to find each
	// other three metres apart.
	if n.sock != nil {
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
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.netMapLocked()
}

// netMapLocked is netMap for callers already holding the lock.
func (n *node) netMapLocked() *netmap.NetMap {
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

	// Snapshot under the lock, then make the call without holding it: a
	// registration is a network round trip, and blocking every status request
	// for its duration would make the UI stutter every time a port is
	// published.
	n.mu.Lock()
	req := &control.RegisterRequest{
		Name:            n.file.Self.Name,
		NodeKey:         n.file.NodeKey.Public(),
		DiscoKey:        n.file.DiscoKey.Public(),
		AuthKey:         n.file.AuthKey,
		AdvertiseRoutes: n.file.AdvertiseRoutes,
		AdvertiseExit:   n.file.AdvertiseExit,
		Services:        n.advertisedServicesLocked(),
	}
	nodeKey, discoKey := n.file.NodeKey, n.file.DiscoKey
	n.mu.Unlock()

	req.Endpoints = n.endpoints()

	resp, err := n.client.Register(ctx, req)
	if err != nil {
		return err
	}

	n.mu.Lock()
	n.file.Self.ID = resp.NodeID
	n.file.Self.Key = nodeKey.Public()
	n.file.Self.DiscoKey = discoKey.Public()
	n.file.Self.Addresses = []netip.Prefix{resp.Address}

	// The auth key has now been redeemed. Keeping it would leave a reusable
	// credential sitting in a file on every machine that ever joined.
	var saveErr error
	if n.file.AuthKey != "" {
		n.file.AuthKey = ""
		saveErr = conf.Save(n.cfgPath, n.file)
	}
	name := n.file.Self.Name
	n.mu.Unlock()

	if saveErr != nil {
		log.Printf("warning: could not clear the stored auth key: %v", saveErr)
	}

	if len(resp.PendingRoutes) > 0 || resp.PendingExit {
		log.Printf("waiting for approval of %s", describePending(resp.PendingRoutes, resp.PendingExit))
		log.Printf("approve with: makima-server routes approve -name %s", name)
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
	n.mu.Lock()
	port := n.file.ListenPort
	n.mu.Unlock()

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
			n.mu.Lock()
			n.lastPollErr = err
			n.mu.Unlock()

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
		n.mu.Lock()
		n.lastPoll = time.Now()
		n.lastPollErr = nil
		n.mu.Unlock()

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

	n.mu.Lock()
	n.file.Self = resp.Self
	n.file.Peers = peers
	n.file.Domain = resp.Domain
	n.file.HomeRelay = resp.HomeRelay

	m := n.netMapLocked()
	n.mu.Unlock()

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

	// Rebind published ports. Almost always a no-op, but the first netmap is
	// where a fresh node learns its address, and every listener depends on it.
	n.applyServices()

	// Persist last, so a cache is only written for a netmap that was actually
	// applied successfully.
	n.mu.Lock()
	saveErr := conf.Save(n.cfgPath, n.file)
	n.mu.Unlock()
	if saveErr != nil {
		log.Printf("cache netmap: %v", saveErr)
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
	if n.serve != nil {
		n.serve.Close()
	}
	if n.inbox != nil {
		n.inbox.Close()
	}
	if n.ssh != nil {
		n.ssh.Close()
	}
	if n.sshKeys != nil {
		n.sshKeys.Close()
	}
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
	n.mu.Lock()
	addr, _ := n.file.Self.Addr()
	mode := "static"
	switch {
	case n.file.Managed():
		mode = n.file.LoginServer
	case n.file.Serverless:
		mode = "serverless"
	}
	name := n.file.Self.Name
	peers := append([]netmap.Node(nil), n.file.Peers...)
	services := append([]serve.Service(nil), n.file.Services...)
	n.mu.Unlock()

	log.Printf("%s up on %s as %s [%s], %d peer(s)", iface, addr, name, mode, len(peers))
	for _, p := range peers {
		logPeer(p)
	}
	for _, s := range services {
		log.Printf("  serving %s", s)
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

// uiPort extracts the port from a -ui address, or 0 when the UI is off.
//
// Needed so the daemon can keep its own web interface off the mesh: with
// -ui-write that page can change this node's settings, and republishing it
// would hand that to anything that can reach the address.
func uiPort(addr string) uint16 {
	if addr == "" {
		return 0
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}
