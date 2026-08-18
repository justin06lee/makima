// Package wg drives the data plane: a userspace WireGuard device bound to a
// TUN interface.
//
// We deliberately use wireguard-go rather than the kernel module even on Linux
// where the kernel one is faster. Userspace gives one identical code path on
// every platform, and — more importantly — it lets a later milestone hand
// WireGuard a custom conn.Bind so packets can be steered over a relay or a
// hole-punched socket without WireGuard knowing the difference. That hook is
// what makes relay-then-upgrade possible at all.
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
	// known yet. A nil endpoint is normal rather than an error: until disco
	// lands in M3 the relay supplies the path, and WireGuard will happily sit
	// with an unset endpoint until the peer speaks first.
	Endpoint  *netip.AddrPort
	Keepalive time.Duration
}

// Config is the complete desired state of the local WireGuard device.
type Config struct {
	PrivateKey key.Private
	ListenPort uint16
	Peers      []Peer
}

// Engine is a running TUN interface plus its WireGuard device.
type Engine struct {
	tun  tun.Device
	dev  *device.Device
	name string
}

// Up creates a TUN interface and starts WireGuard on it.
//
// On macOS the kernel names utun devices itself, so name should be "utun" and
// the real name is read back via Name after creation.
func Up(name string, mtu int, cfg Config, verbose bool) (*Engine, error) {
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
	if verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, fmt.Sprintf("[%s] ", realName))

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	e := &Engine{tun: tunDev, dev: dev, name: realName}

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
	if err := e.dev.IpcSet(uapi(cfg)); err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	return nil
}

// uapi renders a Config into wireguard-go's IPC text protocol.
//
// Field order is load-bearing: replace_peers must precede any peer, and each
// public_key line opens a new peer block that subsequent lines attach to.
func uapi(cfg Config) string {
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
		if p.Endpoint != nil {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint.String())
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
