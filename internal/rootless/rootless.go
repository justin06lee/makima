// Package rootless runs a whole makima node inside one process, touching
// nothing on the machine.
//
// Everything else makima does needs root, and for good reasons: it creates a
// network interface, edits the routing table, writes firewall rules, and
// points the resolver somewhere new. Those are what make a mesh address work
// for *every* program on the machine — ssh, a browser, anything.
//
// They are also, together, an enormous first ask. Somebody evaluating whether
// this works at all has to hand a strange binary root and let it reconfigure
// their network before they have seen it do anything. That is a bad trade for
// them and a bad first impression for makima.
//
// This is the version with the ask removed. WireGuard runs against a userspace
// TCP/IP stack instead of a kernel interface: same engine, same crypto, same
// NAT traversal, same relay — but connections terminate inside this process.
// No interface is created, no route is installed, no firewall rule is written,
// no resolver is touched, and nothing survives the process exiting.
//
// The trade is real and worth stating plainly. Because the host kernel never
// learns the network exists, an arbitrary program cannot use it: you cannot
// point Firefox at a mesh address or run the system `ssh` at one. What you can
// do is everything this process is willing to proxy — forward a port in either
// direction — which turns out to cover most of what a first try is for.
package rootless

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/magicsock"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/pair"
	"github.com/justin06lee/makima/internal/wg"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Options configure a rootless node.
type Options struct {
	// Identity is the node's three keypairs. Zero generates fresh ones, which
	// is the default and the point: an ephemeral node leaves nothing behind
	// and is a different machine every time it starts.
	NodeKey, MachineKey, DiscoKey key.Private

	// Name is what peers call this machine.
	Name string

	// Relay is where to meet peers that cannot be reached directly, and
	// RelayKey the identity it presents.
	Relay    string
	RelayKey key.Public

	Logger *log.Logger
}

// Node is a running rootless makima node.
type Node struct {
	log *log.Logger

	nodeKey  key.Private
	discoKey key.Private
	name     string
	addr     netip.Addr

	sock   *magicsock.Conn
	engine *wg.Engine
	net    *netstack.Net

	mu    sync.Mutex
	peers []netmap.Node

	// relayKey is the identity of the relay in use, kept so a pairing address
	// can name it. Guarded with the peer list because a knock adopts a relay
	// from the address it was given, on a goroutine that is not this one.
	relayKey key.Public

	closeOnce sync.Once
}

// New builds and starts a node. Nothing outside this process changes.
func New(opts Options) (*Node, error) {
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}

	if opts.NodeKey.IsZero() || opts.MachineKey.IsZero() || opts.DiscoKey.IsZero() {
		nodeKey, machineKey, discoKey, err := conf.NewIdentity()
		if err != nil {
			return nil, err
		}
		opts.NodeKey, opts.MachineKey, opts.DiscoKey = nodeKey, machineKey, discoKey
	}

	addr := pair.MeshAddr(opts.NodeKey.Public())

	sock, err := magicsock.New(magicsock.Options{
		NodeKey:  opts.NodeKey,
		DiscoKey: opts.DiscoKey,
		Logger:   opts.Logger,
	})
	if err != nil {
		return nil, err
	}

	// One address, no DNS servers. Mesh names need a resolver the host can
	// see, which is precisely the thing this mode declines to install.
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, wg.DefaultMTU)
	if err != nil {
		sock.Shutdown()
		return nil, fmt.Errorf("rootless: create userspace network: %w", err)
	}

	engine, err := wg.UpOn(tunDev, wg.Config{
		PrivateKey: opts.NodeKey,
		ListenPort: sock.LocalPort(),
	}, wg.Options{
		Bind:     sock,
		Endpoint: magicsock.EndpointString,
	})
	if err != nil {
		sock.Shutdown()
		return nil, err
	}

	n := &Node{
		log:      opts.Logger,
		nodeKey:  opts.NodeKey,
		discoKey: opts.DiscoKey,
		name:     opts.Name,
		addr:     addr,
		sock:     sock,
		engine:   engine,
		net:      tnet,
	}

	if opts.Relay != "" {
		n.relayKey = opts.RelayKey
		n.applyPeers(opts.Relay, opts.RelayKey)
	}
	return n, nil
}

// Addr is this node's mesh address.
func (n *Node) Addr() netip.Addr { return n.addr }

// Close tears everything down. There is nothing to put back.
func (n *Node) Close() {
	n.closeOnce.Do(func() {
		if n.engine != nil {
			n.engine.Close()
		}
		if n.sock != nil {
			n.sock.Shutdown()
		}
	})
}

// Address renders this node's pairing address, for somebody to paste.
func (n *Node) Address(psk key.Shared) (pair.Address, error) {
	a := pair.Address{
		NodeKey:   n.nodeKey.Public(),
		DiscoKey:  n.discoKey.Public(),
		Addr:      n.addr,
		Name:      n.name,
		PSK:       psk,
		Relay:     n.sock.RelayURL(),
		Endpoints: n.endpoints(),
	}
	if a.Relay != "" {
		a.RelayKey = n.currentRelayKey()
	}
	return a, nil
}

// currentRelayKey reads the relay identity under the lock.
func (n *Node) currentRelayKey() key.Public {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.relayKey
}

// endpoints is where this node currently believes it can be reached.
//
// Local interface addresses plus whatever peers and STUN have observed. There
// is no port mapping here: asking a router to forward a port is a change that
// outlives the process, and this mode's promise is that nothing does.
func (n *Node) endpoints() []netip.AddrPort {
	port := n.sock.LocalPort()

	out := localEndpoints(port)
	for _, e := range n.sock.SelfEndpoints() {
		out = appendUnique(out, e)
	}
	return out
}

// Listen opens a pairing window and blocks until somebody knocks or ctx ends.
func (n *Node) Listen(ctx context.Context, a pair.Address, until time.Time) (netmap.Node, error) {
	joined := make(chan magicsock.PairedPeer, 1)

	n.sock.SetPairing(&magicsock.Pairing{
		Token: pair.Token(a),
		Self:  magicsock.PairingSelf{Addr: n.addr, Name: n.name, Endpoints: n.endpoints()},
		Until: until,
		Accept: func(p magicsock.PairedPeer) error {
			if err := n.addPeer(p); err != nil {
				return err
			}
			select {
			case joined <- p:
			default:
			}
			return nil
		},
	})
	defer n.sock.SetPairing(nil)

	select {
	case p := <-joined:
		node, _ := n.peer(p.NodeKey)
		return node, nil
	case <-ctx.Done():
		return netmap.Node{}, errors.New("nobody arrived")
	case <-time.After(time.Until(until)):
		return netmap.Node{}, errors.New("nobody arrived before the window closed")
	}
}

// Knock pairs with a machine that published an address.
func (n *Node) Knock(ctx context.Context, a pair.Address) (netmap.Node, error) {
	// Recorded before the knock, not after: magicsock adopts the address's
	// relay during the exchange, and the peer that lands is applied with
	// whatever relay identity is known at that moment.
	if a.Relay != "" {
		n.mu.Lock()
		n.relayKey = a.RelayKey
		n.mu.Unlock()
	}

	self := magicsock.PairingSelf{Addr: n.addr, Name: n.name, Endpoints: n.endpoints()}

	p, err := n.sock.Knock(ctx, a, self)
	if err != nil {
		return netmap.Node{}, err
	}
	if err := n.addPeer(p); err != nil {
		return netmap.Node{}, err
	}

	node, _ := n.peer(p.NodeKey)
	return node, nil
}

// addPeer records a paired machine and brings it onto the data plane.
func (n *Node) addPeer(p magicsock.PairedPeer) error {
	if !p.Addr.IsValid() {
		return errors.New("the far end offered no mesh address")
	}
	if p.Addr == n.addr {
		return fmt.Errorf("%s derives the same mesh address as this process (%s)", p.Name, p.Addr)
	}

	node := netmap.Node{
		ID:        netmap.NodeID(1),
		Name:      p.Name,
		Key:       p.NodeKey,
		DiscoKey:  p.DiscoKey,
		Addresses: []netip.Prefix{netip.PrefixFrom(p.Addr, p.Addr.BitLen())},
		Endpoints: p.Endpoints,
		RelayURL:  n.sock.RelayURL(),
	}

	n.mu.Lock()
	replaced := false
	for i, existing := range n.peers {
		if existing.Key == p.NodeKey {
			node.ID = existing.ID
			n.peers[i] = node
			replaced = true
			break
		}
	}
	if !replaced {
		node.ID = netmap.NodeID(len(n.peers) + 2)
		n.peers = append(n.peers, node)
	}
	n.mu.Unlock()

	n.applyPeers(n.sock.RelayURL(), n.currentRelayKey())
	return nil
}

// peer looks up a recorded peer by key.
func (n *Node) peer(k key.Public) (netmap.Node, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, p := range n.peers {
		if p.Key == k {
			return p, true
		}
	}
	return netmap.Node{}, false
}

// Peers is everything this node has paired with.
func (n *Node) Peers() []netmap.Node {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]netmap.Node(nil), n.peers...)
}

// applyPeers pushes the current peer set onto WireGuard and the socket.
func (n *Node) applyPeers(relayURL string, relayKey key.Public) {
	n.mu.Lock()
	peers := append([]netmap.Node(nil), n.peers...)
	n.mu.Unlock()

	m := &netmap.NetMap{
		PrivateKey: n.nodeKey,
		ListenPort: n.sock.LocalPort(),
		Peers:      peers,
		HomeRelay:  netmap.Relay{URL: relayURL, Key: relayKey},
	}

	if err := n.engine.SetConfig(m.WireGuardConfig()); err != nil {
		n.log.Printf("rootless: configure tunnel: %v", err)
		return
	}

	cfgs := make([]magicsock.PeerConfig, 0, len(peers))
	for _, p := range peers {
		cfgs = append(cfgs, magicsock.PeerConfig{
			NodeKey:   p.Key,
			DiscoKey:  p.DiscoKey,
			Endpoints: p.Endpoints,
			RelayURL:  p.RelayURL,
		})
	}
	n.sock.SetNetwork(cfgs, relayURL, relayKey)
}

// STUN asks public servers what address this node appears to come from.
func (n *Node) STUN(ctx context.Context, servers []string) error {
	return n.sock.QuerySTUN(ctx, servers)
}

// Direct reports whether the tunnel to a peer is taking a direct path.
func (n *Node) Direct(k key.Public) (bool, time.Duration, string) {
	st, ok := n.sock.PeerStatus(k)
	if !ok {
		return false, 0, ""
	}
	if st.DirectOK {
		return true, st.Latency, st.Direct.String()
	}
	return false, st.RelayLatency, st.RelayURL
}

// Expose forwards a mesh port to something listening on this machine.
//
// The listener lives inside the userspace stack, so nothing is bound on any
// real interface: a peer connecting to meshAddr:port is answered here and
// proxied to target. Nobody else can reach either end.
func (n *Node) Expose(ctx context.Context, port uint16, target string) error {
	ln, err := n.net.ListenTCP(&net.TCPAddr{IP: n.addr.AsSlice(), Port: int(port)})
	if err != nil {
		return fmt.Errorf("listen on the mesh at :%d: %w", port, err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go n.proxyOut(c, target)
		}
	}()
	return nil
}

func (n *Node) proxyOut(from net.Conn, target string) {
	defer from.Close()

	to, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		n.log.Printf("rootless: %s is not answering: %v", target, err)
		return
	}
	defer to.Close()
	splice(from, to)
}

// Forward binds a local port and tunnels it to a peer's port.
//
// The mirror of Expose, and the half that makes this mode usable without any
// system changes: a program on this machine connects to 127.0.0.1 and comes
// out on the peer, with the whole tunnel living inside this process.
func (n *Node) Forward(ctx context.Context, local string, peer netip.Addr, port uint16) (string, error) {
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return "", fmt.Errorf("listen on %s: %w", local, err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	dst := netip.AddrPortFrom(peer, port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go n.proxyIn(ctx, c, dst)
		}
	}()
	return ln.Addr().String(), nil
}

func (n *Node) proxyIn(ctx context.Context, from net.Conn, dst netip.AddrPort) {
	defer from.Close()

	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	to, err := n.net.DialContextTCPAddrPort(dialCtx, dst)
	if err != nil {
		n.log.Printf("rootless: %s is not answering: %v", dst, err)
		return
	}
	defer to.Close()
	splice(from, to)
}

// Dial opens a connection to a peer through the tunnel.
func (n *Node) Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return n.net.DialContextTCPAddrPort(ctx, dst)
}

// ListenMesh accepts connections on a mesh port.
func (n *Node) ListenMesh(port uint16) (net.Listener, error) {
	return n.net.ListenTCP(&net.TCPAddr{IP: n.addr.AsSlice(), Port: int(port)})
}

// splice copies in both directions until either end closes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// localEndpoints is every address on this machine, paired with the socket's
// port.
//
// Duplicated from netcfg rather than shared, because netcfg is the package
// that changes the system and this one exists specifically not to. Importing
// it here would put every route- and resolver-editing function one call away
// from a mode whose entire promise is that it cannot reach them.
func localEndpoints(port uint16) []netip.AddrPort {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var out []netip.AddrPort
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || pair.InMesh(ip) {
				continue
			}
			out = appendUnique(out, netip.AddrPortFrom(ip, port))
		}
	}
	return out
}

func appendUnique(s []netip.AddrPort, a netip.AddrPort) []netip.AddrPort {
	for _, x := range s {
		if x == a {
			return s
		}
	}
	return append(s, a)
}
