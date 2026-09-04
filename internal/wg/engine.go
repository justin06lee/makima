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
	"strings"
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
}

// Up creates a TUN interface and starts WireGuard on it.
//
// On macOS the kernel names utun devices itself, so name should be "utun" and
// the real name is read back via Name after creation.
func Up(name string, cfg Config, opts Options) (*Engine, error) {
	mtu := opts.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}

	tunDev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun %q: %w", name, err)
	}

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
	if opts.Filter != nil {
		devTUN = &filteredTUN{Device: tunDev, allow: opts.Filter}
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

// SetConfig replaces the device's peer set in place.
//
// This is the seam M1 plugs the control plane into: a fresh netmap arrives,
// gets rendered to a Config, and lands here. No interface teardown, so
// existing flows survive a peer list changing underneath them.
func (e *Engine) SetConfig(cfg Config) error {
	if err := e.dev.IpcSet(uapi(cfg, e.endpoint)); err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	return nil
}

// uapi renders a Config into wireguard-go's IPC text protocol.
//
// Field order is load-bearing: replace_peers must precede any peer, and each
// public_key line opens a new peer block that subsequent lines attach to.
func uapi(cfg Config, endpoint EndpointString) string {
	var b strings.Builder

	fmt.Fprintf(&b, "private_key=%s\n", cfg.PrivateKey.Hex())
	fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	b.WriteString("replace_peers=true\n")

	for _, p := range cfg.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", p.PublicKey.Hex())
		b.WriteString("replace_allowed_ips=true\n")
		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip.String())
		}
		if !p.PresharedKey.IsZero() {
			fmt.Fprintf(&b, "preshared_key=%s\n", p.PresharedKey.Hex())
		}
		if ep := endpoint(p); ep != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", ep)
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(p.Keepalive.Seconds()))
		}
	}
	return b.String()
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
