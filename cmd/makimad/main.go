// Command makimad is the node daemon: it brings up the tunnel and keeps it
// matching the netmap.
//
// In static mode the netmap comes from the config file and never changes. In
// managed mode it comes from the control server over a long poll, and every
// update is applied to the running WireGuard device in place — no interface
// teardown, so flows survive peers coming and going.
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
	"syscall"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/wg"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("makimad: ")

	configPath := flag.String("config", conf.DefaultPath, "path to node configuration")
	ifaceName := flag.String("iface", defaultIface, "TUN interface name")
	mtu := flag.Int("mtu", wg.DefaultMTU, "tunnel MTU")
	verbose := flag.Bool("v", false, "log WireGuard handshakes and peer state")
	flag.Parse()

	if err := run(*configPath, *ifaceName, *mtu, *verbose); err != nil {
		log.Fatal(err)
	}
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

	var client *control.Client
	if f.Managed() {
		client = control.NewClient(f.LoginServer, f.ServerKey, f.MachineKey)

		// Register on every start. It is idempotent for a known machine key,
		// and it republishes the node key in case it rotated while we were
		// down — otherwise peers would hold a stale key and every handshake
		// would fail with no indication why.
		if err := register(ctx, client, f); err != nil {
			if len(f.Self.Addresses) == 0 {
				return fmt.Errorf("%w (and no cached netmap to fall back on)", err)
			}
			// A cached netmap is enough to come up. The mesh as of last
			// contact is far better than no mesh at all, and the poll loop
			// will reconcile once the server returns.
			log.Printf("warning: %v", err)
			log.Print("starting from the last known netmap; will keep retrying")
		}
	}

	addr, err := f.Self.Addr()
	if err != nil {
		return err
	}

	engine, err := wg.Up(ifaceName, mtu, f.NetMap().WireGuardConfig(), verbose)
	if err != nil {
		return err
	}
	defer engine.Close()

	router := netcfg.NewRouter(engine.Name())
	if err := router.SetAddr(addr); err != nil {
		return err
	}
	if err := router.Sync(f.NetMap().Routes()); err != nil {
		log.Printf("warning: %v", err)
	}

	logState(engine.Name(), f)

	if client != nil {
		go poll(ctx, client, engine, router, f, configPath)
	}

	down := make(chan struct{})
	go func() { engine.Wait(); close(down) }()

	select {
	case <-ctx.Done():
		log.Print("shutting down")
	case <-down:
		log.Print("device went down")
	}
	return nil
}

// register introduces this node to the control server and records the address
// it was given.
func register(ctx context.Context, client *control.Client, f *conf.File) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := client.Register(ctx, &control.RegisterRequest{
		Name:      f.Self.Name,
		NodeKey:   f.NodeKey.Public(),
		DiscoKey:  f.DiscoKey.Public(),
		Endpoints: netcfg.LocalEndpoints(f.ListenPort),
	})
	if err != nil {
		return err
	}

	f.Self.ID = resp.NodeID
	f.Self.Key = f.NodeKey.Public()
	f.Self.Addresses = []netip.Prefix{resp.Address}
	return nil
}

// poll keeps the local netmap in step with the control server.
func poll(ctx context.Context, client *control.Client, engine *wg.Engine, router *netcfg.Router, f *conf.File, configPath string) {
	var version uint64
	backoff := time.Second

	for ctx.Err() == nil {
		// Re-read on every poll rather than once at startup: a laptop that
		// moves between networks gets a new LAN address, and a peer holding
		// the old one has no way to notice it went stale.
		resp, err := client.PollMap(ctx, version, netcfg.LocalEndpoints(f.ListenPort))
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
			// Cap the backoff: a control server down for an hour should not
			// mean an hour's delay noticing it came back.
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

		f.Self = resp.Self
		f.Peers = resp.Peers

		m := f.NetMap()
		if err := engine.SetConfig(m.WireGuardConfig()); err != nil {
			log.Printf("apply netmap: %v", err)
			continue
		}
		if err := router.Sync(m.Routes()); err != nil {
			log.Printf("warning: %v", err)
		}
		// Persist last, so a cache is only written for a netmap that was
		// actually applied successfully.
		if err := conf.Save(configPath, f); err != nil {
			log.Printf("cache netmap: %v", err)
		}

		log.Printf("netmap v%d: %d peer(s)", version, len(resp.Peers))
		for _, p := range resp.Peers {
			logPeer(p)
		}
	}
}

func logState(iface string, f *conf.File) {
	addr, _ := f.Self.Addr()
	mode := "static"
	if f.Managed() {
		mode = f.LoginServer
	}
	log.Printf("%s up on %s as %s [%s], %d peer(s)", iface, addr, f.Self.Name, mode, len(f.Peers))
	for _, p := range f.Peers {
		logPeer(p)
	}
}

func logPeer(p netmap.Node) {
	via := "no known path"
	if len(p.Endpoints) > 0 {
		via = p.Endpoints[0].String()
	}
	a, _ := p.Addr()
	log.Printf("  peer %-16s %-15s via %s", p.Name, a, via)
}
