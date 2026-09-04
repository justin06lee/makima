// Command makima manages a node's identity and its membership in a mesh.
//
// Two ways in: `init` for a hand-maintained static mesh, `join` for one with a
// control server. The peer subcommand only applies to the former — a managed
// node's peer list belongs to the server, and editing it locally would just be
// overwritten by the next netmap.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
)

// version is stamped by the Makefile from `git describe`.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	// The plug-and-play surface. Everything below it still works and is still
	// reachable; it is simply not what somebody starting out has to read.
	case "up":
		err = upCmd(os.Args[2:])
	case "join":
		err = joinCmd(os.Args[2:])
	case "pair":
		err = pairCmd(os.Args[2:])
	case "try":
		err = tryCmd(os.Args[2:])
	case "invite":
		err = inviteCmd(os.Args[2:])
	case "down":
		err = downCmd(os.Args[2:])
	case "ssh", "possess":
		err = sshCmd(os.Args[2:])
	case "cp":
		err = cpCmd(os.Args[2:])
	case "inbox":
		err = inboxCmd(os.Args[2:])
	case "sshd":
		err = sshdCmd(os.Args[2:])
	case "allow":
		err = serveCmd(os.Args[2:])
	case "deny":
		err = denyCmd(os.Args[2:])

	case "genkey":
		err = genkey(os.Args[2:])
	case "init":
		err = initNode(os.Args[2:])

	case "peer":
		err = peer(os.Args[2:])
	case "show":
		err = show(os.Args[2:])
	case "status":
		err = status(os.Args[2:])
	case "ping":
		err = pingCmd(os.Args[2:])
	case "set":
		err = set(os.Args[2:])
	case "serve":
		err = serveCmd(os.Args[2:])
	case "doctor":
		err = doctor(os.Args[2:])
	case "firewall":
		err = firewallCmd(os.Args[2:])
	case "ui":
		err = uiCmd(os.Args[2:])
	case "version":
		fmt.Println(version)
		return
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
	fmt.Fprint(os.Stderr, `makima — every machine you own, on one private network

getting started:
  makima up                        start. the first machine makes the mesh.
  makima invite                    print an invite for the next machine
  makima join <invite>             run this on that machine
  makima down                      stop, and put this machine back

with no server at all:
  makima pair                      print an address, and listen for one machine
  makima pair <address>            run this on that machine

without root, without changing anything:
  makima try -serve 8080           offer a local port, and print an address
  makima try <address>             run this on the other machine

using it:
  makima status                    what you can see, and anything wrong
  makima ping NAME                 is this peer direct, or going via a relay?
  makima ssh NAME                  a shell on another machine
  makima cp FILE NAME:             send a file to it
  makima inbox                     where files from other machines land
  makima allow 11434               publish a local port on purpose
  makima deny 11434                stop publishing one

Services listening on 127.0.0.1 are published to your mesh as they appear, so
starting Ollama or a dev server is the whole procedure. Your mesh is trusted
like this machine is; run the daemon with -no-auto-serve if that is not what
you want.

everything else:
  makima show          the raw configuration
  makima set           routes and exit nodes
  makima doctor        the long-form diagnosis
  makima firewall      status | allow
  makima sshd          let other machines ssh in, without an sshd
  makima ui            open the web interface
  makima init          start a mesh you maintain by hand
  makima peer          add and remove its peers
  makima genkey        generate a keypair and print it (-psk for a preshared key)

  makima-server        administer the mesh: nodes, access, names, the lock
  makima-relay         the fallback path, for machines that cannot meet directly

every command takes -config PATH (default `+conf.DefaultPath+`)
`)
}

func genkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	psk := fs.Bool("psk", false, "generate a preshared key instead of a keypair")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *psk {
		s, err := key.NewShared()
		if err != nil {
			return err
		}
		// One line and nothing else, because the only useful thing to do with
		// it is paste it into two `makima peer add -psk` commands, and a label
		// in front would have to be stripped off first.
		fmt.Println(s.Base64())
		return nil
	}

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
	if err := checkOverwrite(*path, *force); err != nil {
		return err
	}

	prefix, err := meshPrefix(*addr)
	if err != nil {
		return err
	}
	nodeKey, machineKey, discoKey, err := conf.NewIdentity()
	if err != nil {
		return err
	}

	f := &conf.File{
		NodeKey:    nodeKey,
		MachineKey: machineKey,
		DiscoKey:   discoKey,
		ListenPort: uint16(*port),
		Self: netmap.Node{
			ID:        1,
			Name:      *name,
			Key:       nodeKey.Public(),
			Addresses: []netip.Prefix{prefix},
		},
	}
	if err := conf.Save(*path, f); err != nil {
		return err
	}

	fmt.Printf("wrote %s\n", *path)
	fmt.Printf("node   %s at %s\n", *name, prefix.Addr())
	fmt.Printf("key    %s\n\n", nodeKey.Public())
	fmt.Print("give that public key to your other machines, and add them here with 'makima peer add'.\n")
	return nil
}

func joinNode(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	server := fs.String("server", "", "control server URL, e.g. http://control.example:8080")
	authKey := fs.String("authkey", "", "join credential from 'makima-server authkey'")
	serverKey := fs.String("serverkey", "", "control server's public key; fetched over the network if omitted")
	name := fs.String("name", "", "this node's name (defaults to the hostname)")
	port := fs.Uint("port", 51820, "UDP port WireGuard listens on")
	force := fs.Bool("force", false, "replace an existing configuration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *authKey == "" {
		return fmt.Errorf("join needs -server and -authkey")
	}
	if *name == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("no -name given and the hostname is unreadable: %w", err)
		}
		*name = h
	}
	if err := checkOverwrite(*path, *force); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var srvKey key.Public
	if *serverKey != "" {
		k, err := key.ParsePublic(*serverKey)
		if err != nil {
			return fmt.Errorf("parse -serverkey: %w", err)
		}
		srvKey = k
	} else {
		// Trust-on-first-use. Fine on a network you control, and the reason
		// -serverkey exists for one you do not.
		k, err := control.FetchServerKey(ctx, *server)
		if err != nil {
			return err
		}
		srvKey = k
		fmt.Printf("server key %s (fetched; pin it with -serverkey next time)\n", k)
	}

	nodeKey, machineKey, discoKey, err := conf.NewIdentity()
	if err != nil {
		return err
	}

	client := control.NewClient(*server, srvKey, machineKey)
	resp, err := client.Register(ctx, &control.RegisterRequest{
		Name:      *name,
		NodeKey:   nodeKey.Public(),
		DiscoKey:  discoKey.Public(),
		AuthKey:   *authKey,
		Endpoints: netcfg.LocalEndpoints(uint16(*port)),
	})
	if err != nil {
		return err
	}

	f := &conf.File{
		NodeKey:     nodeKey,
		MachineKey:  machineKey,
		DiscoKey:    discoKey,
		ListenPort:  uint16(*port),
		LoginServer: strings.TrimRight(*server, "/"),
		ServerKey:   srvKey,
		// Kept only until the daemon's first successful registration, which
		// clears it. A node that an operator expires needs to present one
		// again, and there is nobody at the keyboard of a headless machine to
		// type it.
		AuthKey: *authKey,
		Self: netmap.Node{
			ID:        resp.NodeID,
			Name:      *name,
			Key:       nodeKey.Public(),
			Addresses: []netip.Prefix{resp.Address},
		},
	}
	if err := conf.Save(*path, f); err != nil {
		return err
	}

	fmt.Printf("joined %s\n", *server)
	fmt.Printf("node   %s at %s (id %d)\n", *name, resp.Address.Addr(), resp.NodeID)
	fmt.Printf("wrote  %s\n\n", *path)
	fmt.Print("bring the tunnel up with: sudo makimad\n")
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
	psk := fs.String("psk", "", "preshared key shared with this peer (makima genkey -psk)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *pubkey == "" || *addr == "" {
		return fmt.Errorf("peer add needs -name, -key and -addr")
	}

	f, err := loadStatic(*path)
	if err != nil {
		return err
	}

	pub, err := key.ParsePublic(*pubkey)
	if err != nil {
		return err
	}
	if pub == f.Self.Key {
		return fmt.Errorf("that is this node's own key")
	}
	prefix, err := meshPrefix(*addr)
	if err != nil {
		return err
	}

	p := netmap.Node{
		ID:        netmap.NodeID(len(f.Peers) + 2),
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
	if *psk != "" {
		shared, err := key.ParseShared(*psk)
		if err != nil {
			return fmt.Errorf("parse preshared key: %w", err)
		}
		p.PresharedKey = shared
	}

	// Replace rather than duplicate: re-running add after a key rotation is
	// the expected way to update a peer.
	replaced := false
	for i, existing := range f.Peers {
		if existing.Name == *name {
			p.ID = existing.ID
			f.Peers[i] = p
			replaced = true
			break
		}
	}
	if !replaced {
		f.Peers = append(f.Peers, p)
	}

	if err := conf.Save(*path, f); err != nil {
		return err
	}
	verb := "added"
	if replaced {
		verb = "updated"
	}
	fmt.Printf("%s peer %s at %s\n", verb, *name, prefix.Addr())
	if *psk != "" {
		// The failure mode for a one-sided preshared key is a tunnel that
		// never comes up and says nothing about why, so the reminder is worth
		// a line every time rather than a sentence in the manual.
		fmt.Printf("run the matching 'peer add -psk' on %s too — a preshared key set on one side only stops the tunnel entirely\n", *name)
	}
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

	f, err := loadStatic(*path)
	if err != nil {
		return err
	}

	kept := f.Peers[:0]
	found := false
	for _, p := range f.Peers {
		if p.Name == *name {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		return fmt.Errorf("no peer named %q", *name)
	}
	f.Peers = kept

	if err := conf.Save(*path, f); err != nil {
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

	f, err := conf.Load(*path)
	if err != nil {
		return err
	}
	selfAddr, _ := f.Self.Addr()

	fmt.Printf("node   %s\n", f.Self.Name)
	fmt.Printf("addr   %s\n", selfAddr)
	fmt.Printf("key    %s\n", f.Self.Key)
	fmt.Printf("port   %d\n", f.ListenPort)
	if f.Managed() {
		fmt.Printf("server %s\n", f.LoginServer)
		fmt.Printf("       %s\n", f.ServerKey)
	} else {
		fmt.Print("server none (static mesh)\n")
	}

	if len(f.Peers) == 0 {
		if f.Managed() {
			fmt.Print("\nno peers yet — join another machine to this server\n")
		} else {
			fmt.Print("\nno peers yet — add one with 'makima peer add'\n")
		}
		return nil
	}

	fmt.Printf("\n%d peer(s):\n", len(f.Peers))
	for _, p := range f.Peers {
		a, _ := p.Addr()
		via := "no known path"
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

// loadStatic refuses to hand back a managed config for local editing.
func loadStatic(path string) (*conf.File, error) {
	f, err := conf.Load(path)
	if err != nil {
		return nil, err
	}
	if f.Managed() {
		return nil, fmt.Errorf("this node is managed by %s; its peers come from the server, and local edits would be overwritten by the next netmap", f.LoginServer)
	}
	return f, nil
}

func checkOverwrite(path string, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists (pass -force to replace, which rotates this node's identity)", path)
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
	if !netcfg.CGNATRange.Contains(addr) {
		return netip.Prefix{}, fmt.Errorf("%s is outside the mesh range %s", addr, netcfg.CGNATRange)
	}
	return netip.PrefixFrom(addr, 32), nil
}
