package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/invite"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/supervise"
)

// The three long-running processes, and where each keeps its things.
const (
	serverStatePath = "/var/lib/makima/control.json"
	runDir          = "/var/lib/makima"
	logDir          = "/var/log/makima"

	// inviteTTL is how long a fresh invite lasts.
	//
	// An hour, not a day: an invite is a bearer credential and the machine it
	// is for is nearly always sitting right there. Long enough to walk to
	// another room, short enough that one left in a chat log stops mattering
	// before anybody finds it.
	inviteTTL = time.Hour

	startWait = 20 * time.Second
	stopWait  = 15 * time.Second
)

func serverSocket() string { return filepath.Join(runDir, "control.sock") }

func daemonFor(configPath string) supervise.Daemon {
	return supervise.Daemon{
		Name:    "makimad",
		Args:    []string{"-config", configPath},
		Socket:  localapi.SocketPath(configPath),
		PIDFile: filepath.Join(runDir, "makimad.pid"),
		LogFile: filepath.Join(logDir, "makimad.log"),
	}
}

func controlDaemon() supervise.Daemon {
	return supervise.Daemon{
		Name:    "makima-server",
		Args:    []string{"serve", "-state", serverStatePath},
		Socket:  serverSocket(),
		PIDFile: filepath.Join(runDir, "makima-server.pid"),
		LogFile: filepath.Join(logDir, "makima-server.log"),
	}
}

// upCmd is the one command somebody has to know.
//
// With no argument it brings this machine onto a mesh, making one if there is
// not one yet. With an invite it joins somebody else's. Either way it ends with
// a tunnel that is up, and it can be run again at any time without doing
// damage — which matters, because "run it again" is the first thing anybody
// tries and it should not be the thing that breaks it.
func upCmd(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	name := fs.String("name", "", "this machine's name on the mesh (defaults to the hostname)")
	advertise := fs.String("advertise", "", "the address other machines should reach this one at, when it holds the mesh")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// A pasted invite is the whole argument. Accepting it here as well as
	// under `join` means neither one is the wrong guess.
	var inv invite.Invite
	if rest := fs.Args(); len(rest) > 0 {
		var err error
		if inv, err = checkInvite(rest[0]); err != nil {
			return err
		}
	}

	if err := mustBeRoot(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if inv.Server != "" {
		return joinWith(ctx, *path, inv, *name)
	}

	if _, err := conf.Load(*path); err == nil {
		return bringUp(ctx, *path)
	}

	return bootstrap(ctx, *path, *name, *advertise)
}

// bootstrap makes a new mesh on this machine and joins it to itself.
//
// This is the path that removes the hardest step. Somebody who has never used
// a mesh network does not know that a coordination plane exists, that it has to
// run somewhere, or that they are about to become responsible for it. Making
// the first machine the one that holds it — and saying so — turns an
// architecture decision into a sentence they can read afterwards.
func bootstrap(ctx context.Context, path, name, advertise string) error {
	fmt.Println("No mesh here yet — making one, and putting the coordination plane on this machine.")

	server := controlDaemon()
	if err := server.Start(ctx, startWait); err != nil {
		return err
	}

	admin, ok := control.DialAdmin(serverSocket())
	if !ok {
		return fmt.Errorf("the coordination plane started but is not answering on %s", serverSocket())
	}

	serverKey, err := admin.ServerKey()
	if err != nil {
		return fmt.Errorf("read the mesh's public key: %w", err)
	}

	reachable := advertise
	if reachable == "" {
		reachable = guessReachableAddr()
	}
	serverURL := "http://" + net.JoinHostPort(reachable, "8080")

	// Names on by default. There is no reason to make somebody turn on the
	// ability to type a name instead of an address, and every reason not to
	// leave it as a thing they have to find out about.
	if err := admin.SetDNS(true, control.DefaultDomain); err != nil {
		fmt.Fprintf(os.Stderr, "note: mesh names are unavailable: %v\n", err)
	}

	inv, err := mintInvite(admin, serverURL, serverKey)
	if err != nil {
		return err
	}

	decoded, err := checkInvite(inv)
	if err != nil {
		return err
	}
	if err := joinWith(ctx, path, decoded, name); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Add another machine — run this on it:")
	fmt.Printf("  makima join %s\n", inv)
	warnIfUnreachable(reachable)
	return nil
}

// checkInvite decodes a pasted invite and says why it is unusable.
//
// Called before anything asks for a password. Being prompted for root and then
// told the string was mistyped is a bad trade, and the check costs nothing.
func checkInvite(raw string) (invite.Invite, error) {
	inv, err := invite.Decode(raw)
	if err != nil {
		return invite.Invite{}, err
	}
	if inv.Expired() {
		return invite.Invite{}, errors.New("that invite has expired — mint a fresh one with 'makima invite' on the machine holding the mesh")
	}
	return inv, nil
}

// joinWith joins the mesh an invite describes, then brings the tunnel up.
func joinWith(ctx context.Context, path string, inv invite.Invite, name string) error {
	if name == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("no -name given and the hostname is unreadable: %w", err)
		}
		name = h
	}

	if err := registerNode(ctx, path, inv, name); err != nil {
		return err
	}
	return bringUp(ctx, path)
}

// bringUp starts the daemon and prints what the machine can now see.
func bringUp(ctx context.Context, path string) error {
	d := daemonFor(path)
	already := d.Running()
	if err := d.Start(ctx, startWait); err != nil {
		return err
	}
	if !already {
		// The first netmap decides which peers exist, and arriving a moment
		// later would print an empty mesh to somebody who just joined one.
		waitForPeers(path, 5*time.Second)
	}
	return status([]string{"-config", path})
}

// inviteCmd prints a fresh invite for the next machine.
func inviteCmd(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	advertise := fs.String("advertise", "", "the address the joining machine should reach this one at")
	if err := fs.Parse(args); err != nil {
		return err
	}

	admin, ok := control.DialAdmin(serverSocket())
	if !ok {
		return errors.New("this machine does not hold the mesh — run 'makima invite' on the one that does")
	}

	serverKey, err := admin.ServerKey()
	if err != nil {
		return err
	}

	reachable := *advertise
	if reachable == "" {
		reachable = guessReachableAddr()
	}

	inv, err := mintInvite(admin, "http://"+net.JoinHostPort(reachable, "8080"), serverKey)
	if err != nil {
		return err
	}

	fmt.Println("Run this on the machine you are adding:")
	fmt.Printf("  makima join %s\n", inv)
	fmt.Printf("\nGood for %s.\n", inviteTTL)
	warnIfUnreachable(reachable)
	return nil
}

// downCmd stops the tunnel and puts the machine back the way it was.
func downCmd(args []string) error {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	all := fs.Bool("all", false, "also stop the coordination plane, if this machine holds it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := mustBeRoot(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	d := daemonFor(*path)
	if !d.Running() {
		fmt.Println("Already down.")
	} else if err := d.Stop(ctx, stopWait); err != nil {
		return err
	} else {
		fmt.Println("Down. Interface, routes, resolver and firewall rule put back.")
	}

	if *all {
		s := controlDaemon()
		if s.Running() {
			if err := s.Stop(ctx, stopWait); err != nil {
				return err
			}
			fmt.Println("Coordination plane stopped — no machine can join or leave until it is back.")
		}
	}
	return nil
}

// mintInvite bundles a fresh credential with everything else a machine needs.
//
// Single-use, because an invite is for one machine and a reusable one left in
// a chat log admits everybody who reads it.
func mintInvite(admin *control.AdminClient, serverURL string, serverKey key.Public) (string, error) {
	ak, err := admin.MintAuthKey(false, inviteTTL)
	if err != nil {
		return "", fmt.Errorf("mint a credential: %w", err)
	}
	return invite.Encode(invite.Invite{
		Server:    serverURL,
		AuthKey:   ak.Secret,
		ServerKey: serverKey,
		Expires:   time.Now().Add(inviteTTL),
	})
}

// registerNode introduces this machine to the mesh and writes its identity.
//
// The same exchange `makima join` has always performed, with the three flags
// read out of the invite instead of off the command line — which is what makes
// the server key mandatory rather than merely available.
func registerNode(ctx context.Context, path string, inv invite.Invite, name string) error {
	const listenPort = 51820

	if _, err := conf.Load(path); err == nil {
		return fmt.Errorf("this machine is already on a mesh — 'makima down' first, or remove %s to start over", path)
	}

	nodeKey, machineKey, discoKey, err := conf.NewIdentity()
	if err != nil {
		return err
	}

	client := control.NewClient(inv.Server, inv.ServerKey, machineKey)
	resp, err := client.Register(ctx, &control.RegisterRequest{
		Name:      name,
		NodeKey:   nodeKey.Public(),
		DiscoKey:  discoKey.Public(),
		AuthKey:   inv.AuthKey,
		Endpoints: netcfg.LocalEndpoints(listenPort),
	})
	if err != nil {
		return fmt.Errorf("join %s: %w", inv.Server, err)
	}

	f := &conf.File{
		NodeKey:     nodeKey,
		MachineKey:  machineKey,
		DiscoKey:    discoKey,
		ListenPort:  listenPort,
		LoginServer: strings.TrimRight(inv.Server, "/"),
		ServerKey:   inv.ServerKey,
		AuthKey:     inv.AuthKey,
		Self: netmap.Node{
			ID:        resp.NodeID,
			Name:      name,
			Key:       nodeKey.Public(),
			Addresses: []netip.Prefix{resp.Address},
		},
	}
	if err := conf.Save(path, f); err != nil {
		return err
	}

	fmt.Printf("Joined as %s, at %s.\n", name, resp.Address.Addr())
	return nil
}

// mustBeRoot re-runs this command under sudo rather than telling somebody to.
//
// "Permission denied, try again with sudo" is a step, and every step is a place
// to stop. The daemon genuinely needs root — it creates a network interface and
// edits the routing table — so the only question is who types the word, and it
// may as well be the program.
func mustBeRoot() error {
	if os.Geteuid() == 0 {
		return nil
	}

	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return errors.New("this needs root, because it creates a network interface and edits the routing table")
	}

	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}

	fmt.Fprintln(os.Stderr, "makima needs root to create the tunnel — asking sudo.")

	cmd := exec.Command(sudo, append([]string{self}, os.Args[1:]...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	os.Exit(0)
	return nil
}

// guessReachableAddr picks the address other machines should use to reach this
// one's coordination plane.
//
// A guess, and labelled as one wherever it is printed. It asks the routing
// table which source address would be used to reach the internet, which is
// right for a machine with one network interface and is what almost every
// machine is.
func guessReachableAddr() string {
	c, err := net.DialTimeout("udp", "1.1.1.1:53", 2*time.Second)
	if err == nil {
		defer c.Close()
		if host, _, err := net.SplitHostPort(c.LocalAddr().String()); err == nil {
			return host
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "127.0.0.1"
}

// warnIfUnreachable says so when the mesh is being held somewhere the rest of
// the world cannot get to.
//
// The one thing about self-hosting that cannot be automated away. A machine
// behind a home NAT can hold a mesh perfectly well for machines inside the
// house, and a laptop that leaves will keep its tunnel but stop learning about
// changes. Better said now than discovered in a hotel.
func warnIfUnreachable(addr string) {
	ip, err := netip.ParseAddr(addr)
	if err != nil || !ip.IsPrivate() {
		return
	}
	fmt.Println()
	fmt.Printf("Note: %s is a private address, so machines outside this network cannot reach\n", addr)
	fmt.Println("the coordination plane. Everything here works; a laptop that leaves keeps its")
	fmt.Println("tunnel but stops learning about changes. Hold the mesh on a machine with a")
	fmt.Println("public address to avoid that.")
}

// waitForPeers gives the first netmap a moment to land.
func waitForPeers(path string, wait time.Duration) {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		c, err := localapi.Dial(localapi.SocketPath(path))
		if err == nil {
			st, err := c.Status()
			if err == nil && (len(st.Peers) > 0 || !st.Managed) {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// sshCmd opens a shell on a peer.
//
// Sugar, and deliberately so: sshd already listens on every address, so a mesh
// peer is reachable at its name the moment the tunnel is up and `ssh
// desktop.makima` has always worked. What this removes is having to know the
// suffix, and having to remember whether the machine was added as "desktop" or
// "desktop.local".
func sshCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("which machine? (try: makima ssh desktop — 'makima status' lists them)")
	}

	target := args[0]
	rest := args[1:]

	user := ""
	if u, host, ok := strings.Cut(target, "@"); ok {
		user, target = u, host
	}

	host, err := resolvePeer(target)
	if err != nil {
		return err
	}
	if user != "" {
		host = user + "@" + host
	}

	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return errors.New("no ssh client on this machine")
	}

	cmd := exec.Command(ssh, append([]string{host}, rest...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

// resolvePeer turns a name into something ssh can dial, preferring the mesh
// address over the name so it works whether or not mesh DNS is on.
func resolvePeer(name string) (string, error) {
	c, err := localapi.Dial(localapi.SocketPath(conf.DefaultPath))
	if err != nil {
		// No daemon to ask. The name may still resolve, so let ssh try rather
		// than refusing on the strength of our own unavailability.
		return name, nil
	}
	st, err := c.Status()
	if err != nil {
		return name, nil
	}

	bare := strings.TrimSuffix(name, "."+st.Domain)
	for _, p := range st.Peers {
		if p.Name == bare {
			if !p.Online {
				fmt.Fprintf(os.Stderr, "note: %s is not currently reachable on the mesh\n", bare)
			}
			return p.Address.String(), nil
		}
	}

	var names []string
	for _, p := range st.Peers {
		names = append(names, p.Name)
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no peers on this mesh yet — add one with 'makima invite'")
	}
	return "", fmt.Errorf("no machine called %q on this mesh (have: %s)", bare, strings.Join(names, ", "))
}

// joinCmd puts this machine on somebody else's mesh.
//
// Takes one pasted invite. The old flag form — -server, -authkey, -serverkey —
// still works underneath, because a lot of writing refers to it and breaking
// every one of those references at once would be its own kind of unfriendly.
func joinCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("paste the invite: makima join mk1_...  (get one with 'makima invite' on the machine holding the mesh)")
	}
	if strings.HasPrefix(args[0], "-") {
		return joinNode(args)
	}

	fs := flag.NewFlagSet("join", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	name := fs.String("name", "", "this machine's name on the mesh (defaults to the hostname)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	// Before sudo, not after: being asked for a password and then told the
	// invite was mistyped is the wrong order to find that out in.
	inv, err := checkInvite(args[0])
	if err != nil {
		return err
	}
	if err := mustBeRoot(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return joinWith(ctx, *path, inv, *name)
}

// denyCmd stops publishing a port.
//
// The counterpart to allow, and the more important of the two now that
// loopback services are published without being asked for: it is how somebody
// takes one back off the mesh. Denying an automatic service pins it shut, so
// the next scan does not simply publish it again.
func denyCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("which port? (try: makima deny 11434 — 'makima status' lists what is published)")
	}
	return serveRemove(args)
}
