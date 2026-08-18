// Command makima manages a node's identity and peer list.
//
// The peer subcommand is scaffolding with a deliberately short life: it exists
// because M0 has no control plane, and M1 deletes it in favour of a join token.
package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "genkey":
		err = genkey()
	case "init":
		err = initNode(os.Args[2:])
	case "peer":
		err = peer(os.Args[2:])
	case "show":
		err = show(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "makima: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "makima: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `makima — a self-hosted mesh network

usage:
  makima genkey                    generate a keypair and print it
  makima init    -name N -addr A   create this node's configuration
  makima peer add -name N -key K -addr A [-endpoint HOST:PORT]
  makima peer rm  -name N
  makima show                      print the current configuration

every command takes -config PATH (default `+conf.DefaultPath+`)

bring the tunnel up with:  sudo makimad
`)
}

func genkey() error {
	priv, err := key.NewPrivate()
	if err != nil {
		return err
	}
	fmt.Printf("private  %s\n", priv.Base64())
	fmt.Printf("public   %s\n", priv.Public())
	return nil
}

func initNode(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	name := fs.String("name", "", "this node's name")
	addr := fs.String("addr", "", "this node's mesh address, e.g. 100.64.0.1")
	port := fs.Uint("port", 51820, "UDP port WireGuard listens on")
	force := fs.Bool("force", false, "overwrite an existing configuration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *addr == "" {
		return fmt.Errorf("init needs -name and -addr")
	}

	// Refuse to clobber silently: overwriting the private key would evict this
	// node from every peer's allowed list with no way back.
	if _, err := os.Stat(*path); err == nil && !*force {
		return fmt.Errorf("%s already exists (pass -force to replace, which rotates this node's identity)", *path)
	}

	prefix, err := meshPrefix(*addr)
	if err != nil {
		return err
	}
	priv, err := key.NewPrivate()
	if err != nil {
		return err
	}

	m := &netmap.NetMap{
		PrivateKey: priv,
		ListenPort: uint16(*port),
		Self: netmap.Node{
			ID:        1,
			Name:      *name,
			Key:       priv.Public(),
			Addresses: []netip.Prefix{prefix},
		},
	}
	if err := conf.Save(*path, m); err != nil {
		return err
	}

	fmt.Printf("wrote %s\n", *path)
	fmt.Printf("node   %s at %s\n", *name, prefix.Addr())
	fmt.Printf("key    %s\n\n", priv.Public())
	fmt.Print("give that public key to your other machines, and add them here with 'makima peer add'.\n")
	return nil
}

func peer(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("peer needs a subcommand: add or rm")
	}
	switch args[0] {
	case "add":
		return peerAdd(args[1:])
	case "rm", "remove":
		return peerRemove(args[1:])
	default:
		return fmt.Errorf("unknown peer subcommand %q", args[0])
	}
}

func peerAdd(args []string) error {
	fs := flag.NewFlagSet("peer add", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	name := fs.String("name", "", "peer name")
	pubkey := fs.String("key", "", "peer public key")
	addr := fs.String("addr", "", "peer mesh address")
	endpoint := fs.String("endpoint", "", "peer's reachable HOST:PORT, if known")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *pubkey == "" || *addr == "" {
		return fmt.Errorf("peer add needs -name, -key and -addr")
	}

	m, err := conf.Load(*path)
	if err != nil {
		return err
	}

	pub, err := key.ParsePublic(*pubkey)
	if err != nil {
		return err
	}
	if pub == m.Self.Key {
		return fmt.Errorf("that is this node's own key")
	}
	prefix, err := meshPrefix(*addr)
	if err != nil {
		return err
	}

	p := netmap.Node{
		ID:        netmap.NodeID(len(m.Peers) + 2),
		Name:      *name,
		Key:       pub,
		Addresses: []netip.Prefix{prefix},
	}
	if *endpoint != "" {
		ap, err := netip.ParseAddrPort(*endpoint)
		if err != nil {
			return fmt.Errorf("parse endpoint %q: %w", *endpoint, err)
		}
		p.Endpoints = []netip.AddrPort{ap}
	}

	// Replace rather than duplicate: re-running add after a key rotation is
	// the expected way to update a peer.
	replaced := false
	for i, existing := range m.Peers {
		if existing.Name == *name {
			p.ID = existing.ID
			m.Peers[i] = p
			replaced = true
			break
		}
	}
	if !replaced {
		m.Peers = append(m.Peers, p)
	}

	if err := conf.Save(*path, m); err != nil {
		return err
	}
	verb := "added"
	if replaced {
		verb = "updated"
	}
	fmt.Printf("%s peer %s at %s\n", verb, *name, prefix.Addr())
	return nil
}

func peerRemove(args []string) error {
	fs := flag.NewFlagSet("peer rm", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	name := fs.String("name", "", "peer name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("peer rm needs -name")
	}

	m, err := conf.Load(*path)
	if err != nil {
		return err
	}
	kept := m.Peers[:0]
	found := false
	for _, p := range m.Peers {
		if p.Name == *name {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		return fmt.Errorf("no peer named %q", *name)
	}
	m.Peers = kept
	if err := conf.Save(*path, m); err != nil {
		return err
	}
	fmt.Printf("removed peer %s\n", *name)
	return nil
}

func show(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	m, err := conf.Load(*path)
	if err != nil {
		return err
	}
	selfAddr, _ := m.Self.Addr()

	fmt.Printf("node   %s\n", m.Self.Name)
	fmt.Printf("addr   %s\n", selfAddr)
	fmt.Printf("key    %s\n", m.Self.Key)
	fmt.Printf("port   %d\n", m.ListenPort)

	if len(m.Peers) == 0 {
		fmt.Print("\nno peers yet — add one with 'makima peer add'\n")
		return nil
	}
	fmt.Printf("\n%d peer(s):\n", len(m.Peers))
	for _, p := range m.Peers {
		a, _ := p.Addr()
		via := "no known path (needs -endpoint until the relay lands)"
		if len(p.Endpoints) > 0 {
			var eps []string
			for _, e := range p.Endpoints {
				eps = append(eps, e.String())
			}
			via = strings.Join(eps, ", ")
		}
		fmt.Printf("  %-16s %-15s %s\n", p.Name, a, via)
		fmt.Printf("  %-16s %s\n", "", p.Key)
	}
	return nil
}

// meshPrefix parses a mesh address and pins it to a /32.
//
// Every node's own address is a single host route; the prefix type exists for
// subnet routers, which advertise real CIDRs later on.
func meshPrefix(s string) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse address %q: %w", s, err)
	}
	if !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("mesh addresses are IPv4 for now, got %q", s)
	}
	if !netcfgRange().Contains(addr) {
		return netip.Prefix{}, fmt.Errorf("%s is outside the mesh range %s", addr, netcfgRange())
	}
	return netip.PrefixFrom(addr, 32), nil
}
