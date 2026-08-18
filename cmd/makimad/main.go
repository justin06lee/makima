// Command makimad is the node daemon: it brings up the tunnel and keeps it
// matching the netmap.
//
// M0 reads a static peer list and holds it. M1 replaces that single Load call
// with a long-poll against the control server, and everything below it — the
// TUN device, the WireGuard engine, the address and route wiring — stays as
// it is.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/netcfg"
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

	m, err := conf.Load(configPath)
	if err != nil {
		return err
	}

	addr, err := m.Self.Addr()
	if err != nil {
		return err
	}

	engine, err := wg.Up(ifaceName, mtu, m.WireGuardConfig(), verbose)
	if err != nil {
		return err
	}
	defer engine.Close()

	if err := netcfg.Configure(engine.Name(), addr, m.Routes()); err != nil {
		return err
	}

	log.Printf("%s up on %s as %s (%s), %d peer(s)",
		engine.Name(), addr, m.Self.Name, m.Self.Key, len(m.Peers))
	for _, p := range m.Peers {
		via := "no known path"
		if len(p.Endpoints) > 0 {
			via = p.Endpoints[0].String()
		}
		a, _ := p.Addr()
		log.Printf("  peer %-16s %-15s via %s", p.Name, a, via)
	}

	// Wait for either the operator or the OS to end it. The engine's own Wait
	// covers the case where the interface is torn down externally, which
	// otherwise leaves the daemon alive holding a dead tunnel.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	down := make(chan struct{})
	go func() { engine.Wait(); close(down) }()

	select {
	case s := <-sig:
		log.Printf("caught %s, shutting down", s)
	case <-down:
		log.Print("device went down")
	}
	return nil
}
