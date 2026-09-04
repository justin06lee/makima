package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/pair"
	"github.com/justin06lee/makima/internal/rootless"
	"github.com/justin06lee/makima/internal/stun"
)

// `makima try` is makima with the root prompt removed.
//
// Everything else here needs root, for good reasons: creating an interface,
// editing the routing table, writing firewall rules and pointing the resolver
// somewhere new are what make a mesh address work for *every* program on the
// machine. They are also, together, an enormous first ask. Somebody finding
// out whether this works at all has to hand a strange binary root and let it
// reconfigure their network before they have seen it do anything.
//
// This mode removes the ask entirely. WireGuard runs against a userspace
// TCP/IP stack instead of a kernel interface — same engine, same crypto, same
// NAT traversal, same relay — and connections terminate inside this process.
// Nothing is created, nothing is installed, nothing is written, and nothing
// survives Ctrl-C.
//
// The trade is real and is said out loud rather than discovered: because the
// host kernel never learns the network exists, an arbitrary program cannot use
// it. You cannot point a browser at a mesh address. What you can do is
// everything this process will proxy — a port in either direction — which
// turns out to be most of what a first try is for.

func tryCmd(args []string) error {
	fs := flag.NewFlagSet("try", flag.ExitOnError)
	name := fs.String("name", "", "what to call this machine (defaults to the hostname)")
	serve := fs.String("serve", "", "local ports to offer the other machine, e.g. 8080 or 8080,5432")
	forward := fs.String("forward", "", "bring one of their ports here, as LOCAL:REMOTE — e.g. 18080:8080")
	relayURL := fs.String("relay", "", "a relay to meet at, HOST:PORT — needed when neither machine is directly reachable")
	relayKeyStr := fs.String("relay-key", "", "the relay's public key")
	psk := fs.String("psk", "", "a preshared key to bind the pairing to (makima genkey -psk)")
	window := fs.Duration("for", pair.DefaultWindow, "how long to wait for the other machine")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var target pair.Address
	haveTarget := false
	if rest := fs.Args(); len(rest) > 0 {
		var err error
		if target, err = pair.Decode(rest[0]); err != nil {
			return err
		}
		haveTarget = true
	}

	shared, err := parsePSK(*psk)
	if err != nil {
		return err
	}
	relayKey, err := parsePublic(*relayKeyStr)
	if err != nil {
		return fmt.Errorf("parse relay key: %w", err)
	}

	if *name == "" {
		if h, err := os.Hostname(); err == nil {
			*name = h
		} else {
			*name = "somebody"
		}
	}

	node, err := rootless.New(rootless.Options{
		Name:     *name,
		Relay:    *relayURL,
		RelayKey: relayKey,
		Logger:   log.New(quietUnlessAsked(), "", 0),
	})
	if err != nil {
		return err
	}
	defer node.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Public addresses first, so the pairing address about to be printed names
	// somewhere a machine behind NAT can actually be reached.
	discoverEndpoints(ctx, node)

	fmt.Printf("This machine is %s at %s. Nothing on it has been changed.\n\n", *name, node.Addr())

	var peer netmap.Node
	if haveTarget {
		if shared != (key.Shared{}) {
			target.PSK = shared
		}
		fmt.Println("Knocking…")
		if peer, err = node.Knock(ctx, target); err != nil {
			return fmt.Errorf("%w — is 'makima try' still running there?", err)
		}
	} else {
		if peer, err = tryListen(ctx, node, shared, *window); err != nil {
			return err
		}
	}

	peerAddr, err := peer.Addr()
	if err != nil {
		return err
	}
	fmt.Printf("\nPaired with %s at %s.\n", peer.Name, peerAddr)

	if err := tryServe(ctx, node, *serve); err != nil {
		return err
	}
	if err := tryForward(ctx, node, peerAddr, *forward); err != nil {
		return err
	}
	if *serve == "" && *forward == "" {
		fmt.Println()
		fmt.Println("Nothing to carry. -serve 8080 offers a local port to them;")
		fmt.Println("-forward 18080:8080 brings one of theirs here.")
	}

	reportPath(node, peer)

	fmt.Println("\nCtrl-C ends it. Nothing is left behind.")
	<-ctx.Done()
	fmt.Println("\nGone.")
	return nil
}

// tryListen publishes an address and waits for somebody to knock on it.
func tryListen(ctx context.Context, node *rootless.Node, psk key.Shared, window time.Duration) (netmap.Node, error) {
	a, err := node.Address(psk)
	if err != nil {
		return netmap.Node{}, err
	}
	encoded, err := pair.Encode(a)
	if err != nil {
		return netmap.Node{}, fmt.Errorf("%w — this machine has no address anyone could reach it at; give it a relay with -relay HOST:PORT", err)
	}

	fmt.Println("Run this on the other machine:")
	fmt.Println()
	fmt.Printf("  makima try %s\n", encoded)
	fmt.Println()
	fmt.Printf("Waiting up to %s…\n", window.Round(time.Second))

	return node.Listen(ctx, a, time.Now().Add(window))
}

// tryServe offers local ports to the paired machine.
func tryServe(ctx context.Context, node *rootless.Node, spec string) error {
	if spec == "" {
		return nil
	}

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		port, err := parsePort(part)
		if err != nil {
			return err
		}
		target := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
		if err := node.Expose(ctx, port, target); err != nil {
			return err
		}
		fmt.Printf("  offering  %s → %s:%d on the mesh\n", target, node.Addr(), port)
	}
	return nil
}

// tryForward brings one of the peer's ports onto this machine.
func tryForward(ctx context.Context, node *rootless.Node, peer netip.Addr, spec string) error {
	if spec == "" {
		return nil
	}

	localPort, remotePort, err := parseForward(spec)
	if err != nil {
		return err
	}

	local := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(localPort)))
	bound, err := node.Forward(ctx, local, peer, remotePort)
	if err != nil {
		return err
	}
	fmt.Printf("  carrying  http://%s → %s:%d\n", bound, peer, remotePort)
	return nil
}

// parseForward reads "LOCAL:REMOTE", or a bare port meaning both.
func parseForward(spec string) (local, remote uint16, err error) {
	l, r, ok := strings.Cut(spec, ":")
	if !ok {
		// A single number is the common case and means the same port on both
		// sides, which is what somebody typing one thing expects.
		p, err := parsePort(spec)
		return p, p, err
	}

	if local, err = parsePort(l); err != nil {
		return 0, 0, err
	}
	remote, err = parsePort(r)
	return local, remote, err
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%q is not a port", s)
	}
	return uint16(n), nil
}

func parsePSK(s string) (key.Shared, error) {
	if s == "" {
		return key.Shared{}, nil
	}
	k, err := key.ParseShared(s)
	if err != nil {
		return key.Shared{}, fmt.Errorf("parse preshared key: %w", err)
	}
	return k, nil
}

func parsePublic(s string) (key.Public, error) {
	if s == "" {
		return key.Public{}, nil
	}
	return key.ParsePublic(s)
}

// discoverEndpoints asks public STUN servers what address this machine appears
// to come from, so the printed pairing address names somewhere reachable.
//
// Bounded and best-effort. On a LAN the local addresses in the pairing address
// are enough on their own, and behind a NAT that answers nothing there is no
// public address to find — in which case a relay is the answer and the error
// message says so.
func discoverEndpoints(ctx context.Context, node *rootless.Node) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if err := node.STUN(ctx, stun.DefaultServers); err != nil {
		return
	}
	// The answers arrive on the socket's ordinary receive path, so there is
	// nothing to wait on but time.
	select {
	case <-time.After(700 * time.Millisecond):
	case <-ctx.Done():
	}
}

// reportPath says whether the tunnel went direct, which is the one thing about
// it worth knowing and the thing that is otherwise invisible.
func reportPath(node *rootless.Node, peer netmap.Node) {
	// A moment for the first probes to come back. The tunnel works either way;
	// this only decides which sentence is printed.
	time.Sleep(1500 * time.Millisecond)

	direct, latency, where := node.Direct(peer.Key)
	switch {
	case direct && latency > 0:
		fmt.Printf("\nDirect path to %s (%s).\n", where, latency.Round(time.Millisecond))
	case direct:
		fmt.Printf("\nDirect path to %s.\n", where)
	case where != "":
		fmt.Printf("\nGoing through the relay at %s for now; it may still upgrade.\n", where)
	}
}

// quietUnlessAsked keeps the tunnel's own logging out of the way.
//
// This command's output is meant to be read by somebody trying makima for the
// first time, and a WireGuard handshake trace in the middle of it is noise.
// MAKIMA_DEBUG=1 puts it back, which is what anybody diagnosing a failure to
// pair actually wants.
func quietUnlessAsked() io.Writer {
	if os.Getenv("MAKIMA_DEBUG") != "" {
		return os.Stderr
	}
	return io.Discard
}
