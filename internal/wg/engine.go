// Package wg drives the data plane: a userspace WireGuard device bound to a
// TUN interface.
//
// We deliberately use wireguard-go rather than the kernel module even on Linux
// where the kernel one is faster. Userspace gives one identical code path on
// every platform, and — more importantly — it lets the engine be handed a
// custom conn.Bind so packets can be steered over a relay or a hole-punched
// socket without WireGuard knowing the difference. That hook is what makes
// relay-then-upgrade possible at all, and internal/magicsock is what uses it.
package wg

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// DefaultMTU matches Tailscale's choice. 1280 is the IPv6 minimum link MTU, so
// a packet that fits here survives any path without fragmenting — worth more
// than the handful of bytes a larger MTU would buy.
const DefaultMTU = 1280

// Peer is one reachable node in the mesh.
type Peer struct {
	PublicKey  key.Public
	AllowedIPs []netip.Prefix
	// Endpoint is where to send this peer's traffic, or nil when no path is
	// known yet. A nil endpoint is normal rather than an error: with magicsock
	// the relay supplies the path until disco finds a direct one, and with the
	// default bind WireGuard sits unset until the peer speaks first.
	Endpoint  *netip.AddrPort
	Keepalive time.Duration

	// PresharedKey is an optional symmetric secret mixed into this peer's
	// handshake. Zero means none, which is also how WireGuard itself spells
	// "no preshared key", so the common case needs no special handling.
	//
	// It must match on both ends exactly. A one-sided preshared key is not a
	// weaker tunnel, it is no tunnel at all: the handshake simply fails, with
	// no message saying why. That asymmetry is the reason makima only ever
	// sets one from a source both ends read from — a pairing address, or a
	// static config an operator wrote twice on purpose.
	PresharedKey key.Shared
}

// Config is the complete desired state of the local WireGuard device.
type Config struct {
	PrivateKey key.Private
	ListenPort uint16
	Peers      []Peer
}

// EndpointString is how a peer's endpoint is written into WireGuard's
// configuration.
//
// Ordinarily this is an address, and with the default bind it must be. A
// custom bind may define its own form — magicsock uses the peer's node key,
// because the whole point there is that a peer does not have one fixed address
// — so rendering the endpoint is the bind's business, not this package's.
type EndpointString func(p Peer) string

// addrEndpoint is the default: the literal address, which is what stock
// WireGuard expects.
func addrEndpoint(p Peer) string {
	if p.Endpoint == nil {
		return ""
	}
	return p.Endpoint.String()
}

// Engine is a running TUN interface plus its WireGuard device.
type Engine struct {
	tun      tun.Device
	dev      *device.Device
	name     string
	endpoint EndpointString

	// mu serialises SetConfig, and applied is the configuration the device
	// was last given successfully, nil before the first one or after a
	// failure left the device's state unknown.
	mu      sync.Mutex
	applied *Config
}

// Options configure a device beyond its peer set.
type Options struct {
	// MTU of the tunnel. Zero means DefaultMTU.
	MTU int

	// Verbose logs WireGuard handshakes and peer state.
	Verbose bool

	// Bind replaces the UDP socket WireGuard would open for itself.
	//
	// This is the hook the whole architecture rests on. A default bind sends
	// each packet to a fixed address, which is all stock WireGuard can do; a
	// custom one can decide per packet whether a peer is currently reachable
	// directly or has to go through a relay, and switch between them without
	// WireGuard noticing. Leaving it nil gives ordinary WireGuard behaviour,
	// which is exactly right for a static mesh that has no control plane to
	// tell it about relays.
	Bind conn.Bind

	// Endpoint renders a peer's endpoint for the configuration. It must match
	// whatever Bind.ParseEndpoint accepts. Nil means the literal address.
	Endpoint EndpointString

	// Filter is consulted for every decrypted packet before it reaches the
	// host. Nil means no filtering.
	//
	// It is called on the data path for every inbound packet, so it must be
	// cheap and must not block — the policy guard swaps its rules through an
	// atomic pointer for exactly this reason.
	Filter InboundFilter

	// Outbound is shown every packet the host sends into the tunnel, so the
	// filter can recognise the replies to it. Same constraints as Filter.
	Outbound OutboundObserver
}

// Up creates a TUN interface and starts WireGuard on it.
//
// On macOS the kernel names utun devices itself, so name should be "utun" and
// the real name is read back via Name after creation.
//
// This needs root, because creating a network interface does. UpOn is the same
// engine without that requirement.
func Up(name string, cfg Config, opts Options) (*Engine, error) {
	mtu := opts.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}

	tunDev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun %q: %w", name, err)
	}
	return UpOn(tunDev, cfg, opts)
}

// UpOn starts WireGuard on a TUN device the caller already has.
//
// The device does not have to be a kernel interface. A userspace TCP/IP stack
// presents the same interface — packets in, packets out — and swapping one in
// removes every reason this ever needed root: no interface to create, no route
// to install, no firewall rule, no resolver to edit. What it costs is that the
// tunnel is reachable only from inside this process, since the host kernel
// never learns the network exists.
//
// Both are the same engine. The difference is entirely in what is on the other
// side of the TUN, which is exactly the seam wireguard-go was designed around.
func UpOn(tunDev tun.Device, cfg Config, opts Options) (*Engine, error) {
	realName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("read tun name: %w", err)
	}

	level := device.LogLevelError
	if opts.Verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, fmt.Sprintf("[%s] ", realName))

	bind := opts.Bind
	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	endpoint := opts.Endpoint
	if endpoint == nil {
		endpoint = addrEndpoint
	}

	// The filter wraps the device rather than the other way round, so the real
	// TUN is still what gets closed and what reports its own name.
	var devTUN tun.Device = tunDev
	if opts.Filter != nil || opts.Outbound != nil {
		allow := opts.Filter
		if allow == nil {
			allow = func([]byte) bool { return true }
		}
		devTUN = &filteredTUN{Device: tunDev, allow: allow, saw: opts.Outbound}
	}

	dev := device.NewDevice(devTUN, bind, logger)

	e := &Engine{tun: tunDev, dev: dev, name: realName, endpoint: endpoint}

	if err := e.SetConfig(cfg); err != nil {
		e.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		e.Close()
		return nil, fmt.Errorf("bring device up: %w", err)
	}
	return e, nil
}

// SetConfig brings the device's configuration to cfg in place.
//
// This is the seam the control plane plugs into: a fresh netmap arrives, gets
// rendered to a Config, and lands here — which happens every time anything in
// the mesh changes, a published port included. So only what differs from the
// last configuration is sent. Replacing the whole peer set would throw away
// every peer's session keys, making every tunnel in the mesh handshake again
// for a change that had nothing to do with it; restating the listen port would
// close and reopen the UDP socket under live traffic. A peer whose entry did
// not change is not touched at all.
func (e *Engine) SetConfig(cfg Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	text := uapi(cfg, e.endpoint)
	if e.applied != nil {
		text = uapiDiff(*e.applied, cfg, e.endpoint)
	}
	if text == "" {
		return nil
	}
	if err := e.dev.IpcSet(text); err != nil {
		// Part of it may have landed. Nothing is known about the device's
		// state now, so the next configuration is sent whole.
		e.applied = nil
		return fmt.Errorf("configure wireguard: %w", err)
	}
	applied := cfg.clone()
	e.applied = &applied
	return nil
}

// clone copies a Config deeply enough that the caller changing its slices
// afterwards cannot change what the engine believes it applied.
func (c Config) clone() Config {
	out := c
	out.Peers = make([]Peer, len(c.Peers))
	for i, p := range c.Peers {
		p.AllowedIPs = slices.Clone(p.AllowedIPs)
		if p.Endpoint != nil {
			ep := *p.Endpoint
			p.Endpoint = &ep
		}
		out.Peers[i] = p
	}
	return out
}

// uapi renders a whole Config into wireguard-go's IPC text protocol, replacing
// whatever the device held. Used for the first configuration, and after a
// failure leaves the device's state unknown.
//
// Field order is load-bearing: replace_peers must precede any peer, and each
// public_key line opens a new peer block that subsequent lines attach to.
func uapi(cfg Config, endpoint EndpointString) string {
	var b strings.Builder

	fmt.Fprintf(&b, "private_key=%s\n", cfg.PrivateKey.Hex())
	fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	b.WriteString("replace_peers=true\n")

	for _, p := range cfg.Peers {
		writePeer(&b, p, endpoint)
	}
	return b.String()
}

// uapiDiff renders only what changed between two configurations: the peers
// that left, the peers that arrived, and the fields that moved on the peers
// that stayed. Empty when nothing did.
//
// A peer that stays is addressed with update_only, so a stale diff can never
// resurrect a peer that something else removed.
func uapiDiff(old, cfg Config, endpoint EndpointString) string {
	var b strings.Builder

	if old.PrivateKey != cfg.PrivateKey {
		fmt.Fprintf(&b, "private_key=%s\n", cfg.PrivateKey.Hex())
	}
	if old.ListenPort != cfg.ListenPort {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	}

	was := make(map[key.Public]Peer, len(old.Peers))
	for _, p := range old.Peers {
		was[p.PublicKey] = p
	}
	stays := make(map[key.Public]bool, len(cfg.Peers))
	for _, p := range cfg.Peers {
		stays[p.PublicKey] = true
	}

	for _, p := range old.Peers {
		if !stays[p.PublicKey] {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", p.PublicKey.Hex())
		}
	}

	for _, p := range cfg.Peers {
		prev, ok := was[p.PublicKey]
		if !ok {
			writePeer(&b, p, endpoint)
			continue
		}

		var lines strings.Builder
		if !slices.Equal(prev.AllowedIPs, p.AllowedIPs) {
			lines.WriteString("replace_allowed_ips=true\n")
			for _, ip := range p.AllowedIPs {
				fmt.Fprintf(&lines, "allowed_ip=%s\n", ip.String())
			}
		}
		if prev.PresharedKey != p.PresharedKey {
			// All zeroes is how UAPI spells "none", so removing a key is the
			// same line as setting one.
			fmt.Fprintf(&lines, "preshared_key=%s\n", p.PresharedKey.Hex())
		}
		// An endpoint the configuration has not moved is left alone, so the
		// address WireGuard roamed to — the one the peer is actually
		// answering from — is not reset to a stale one on every netmap.
		if ep := endpoint(p); ep != "" && ep != endpoint(prev) {
			fmt.Fprintf(&lines, "endpoint=%s\n", ep)
		}
		if prev.Keepalive != p.Keepalive {
			fmt.Fprintf(&lines, "persistent_keepalive_interval=%d\n", int(p.Keepalive.Seconds()))
		}
		if lines.Len() > 0 {
			fmt.Fprintf(&b, "public_key=%s\nupdate_only=true\n", p.PublicKey.Hex())
			b.WriteString(lines.String())
		}
	}
	return b.String()
}

// writePeer renders one whole peer block.
func writePeer(b *strings.Builder, p Peer, endpoint EndpointString) {
	fmt.Fprintf(b, "public_key=%s\n", p.PublicKey.Hex())
	b.WriteString("replace_allowed_ips=true\n")
	for _, ip := range p.AllowedIPs {
		fmt.Fprintf(b, "allowed_ip=%s\n", ip.String())
	}
	if !p.PresharedKey.IsZero() {
		fmt.Fprintf(b, "preshared_key=%s\n", p.PresharedKey.Hex())
	}
	if ep := endpoint(p); ep != "" {
		fmt.Fprintf(b, "endpoint=%s\n", ep)
	}
	if p.Keepalive > 0 {
		fmt.Fprintf(b, "persistent_keepalive_interval=%d\n", int(p.Keepalive.Seconds()))
	}
}

// Name is the OS-assigned interface name, e.g. "utun6" or "makima0".
func (e *Engine) Name() string { return e.name }

// Wait blocks until the device is shut down, either by Close or by the OS
// tearing the interface out from under us.
func (e *Engine) Wait() { <-e.dev.Wait() }

// Close tears down WireGuard and the interface.
func (e *Engine) Close() error {
	if e.dev != nil {
		e.dev.Close() // also closes the underlying TUN
		return nil
	}
	if e.tun != nil {
		return e.tun.Close()
	}
	return nil
}
