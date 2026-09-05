package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/invite"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/relay"
	"github.com/justin06lee/makima/internal/sshd"
	"github.com/justin06lee/makima/internal/supervise"
)

// The three long-running processes, and where each keeps its things.
const (
	serverStatePath = "/var/lib/makima/control.json"
	runDir          = "/var/lib/makima"
	logDir          = "/var/log/makima"
	relayStatePath  = "/var/lib/makima/relay.json"

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

// serverSocket is where the network's server answers admin requests.
//
// Asked of the control package rather than spelled out here: the server names
// its own socket, and a second spelling of that name in this file is how
// `makima up` once spent twenty seconds waiting on a path nothing listened on,
// then took down a server that had been up the whole time.
func serverSocket() string { return control.SocketPath(serverStatePath) }

// daemonFor is the node daemon, registered with the machine so it is back
// after a reboot. It carries the name of whoever ran makima, because a daemon
// launchd starts at boot has no sudo behind it to say so, and the daemon needs
// to know whose desktop socket to open and whose Downloads to put files in.
func daemonFor(configPath string) supervise.Daemon {
	d := supervise.Daemon{
		Name:    "makimad",
		Args:    []string{"-config", configPath},
		Socket:  localapi.SocketPath(configPath),
		PIDFile: filepath.Join(runDir, "makimad.pid"),
		LogFile: filepath.Join(logDir, "makimad.log"),
		Service: supervise.Service{
			Label:       "sh.makima.makimad",
			Unit:        "makimad",
			Description: "makima: this machine's tunnel",
		},
	}
	if u := invokerFromEnv(); u != nil && u.Username != "" {
		d.Env = map[string]string{"MAKIMA_OWNER": u.Username}
	}
	return d
}

func controlDaemon() supervise.Daemon {
	return supervise.Daemon{
		Name:    "makima-server",
		Args:    []string{"serve", "-state", serverStatePath},
		Socket:  serverSocket(),
		PIDFile: filepath.Join(runDir, "makima-server.pid"),
		LogFile: filepath.Join(logDir, "makima-server.log"),
		Service: supervise.Service{
			Label:       "sh.makima.server",
			Unit:        "makima-server",
			Description: "makima: the network's server",
		},
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
	advertise := fs.String("advertise", "", "where other machines reach this one: a host, host:port, or full URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// A pasted invite is the whole argument, and typed words are several.
	// Accepting either here as well as under `join` means neither one is the
	// wrong guess.
	var inv invite.Invite
	if rest := fs.Args(); len(rest) > 0 {
		var err error
		if inv, err = checkInvite(strings.Join(rest, " ")); err != nil {
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
	fmt.Println("No network here yet — starting one. This machine holds it; the others join through it.")

	server := controlDaemon()
	if err := server.Start(ctx, startWait); err != nil {
		return err
	}

	admin, ok := control.DialAdmin(serverSocket())
	if !ok {
		return fmt.Errorf("the network's server started but is not answering on %s", serverSocket())
	}

	serverKey, err := admin.ServerKey()
	if err != nil {
		return fmt.Errorf("read the mesh's public key: %w", err)
	}

	reachable := advertise
	if reachable == "" {
		reachable = guessReachableAddr()
	}
	serverURL := controlURL(reachable)

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
	words, err := mintWords(admin, serverURL)
	if err != nil {
		return err
	}

	// A machine with a public address is the only kind that can hold a mesh
	// usable from outside the house, and it is also the only kind that can be
	// a relay. Since it is already both, make it both.
	startRelayIfPublic(ctx, admin, reachable)

	decoded, err := checkInvite(inv)
	if err != nil {
		return err
	}
	if err := joinWith(ctx, path, decoded, name); err != nil {
		return err
	}

	fmt.Println()
	printInvite(words, inv)
	warnIfUnreachable(reachable)
	installDieAlias()
	linkCLIQuietly()
	return nil
}

// checkInvite decodes a pasted invite, or typed words, and says why it is
// unusable.
//
// Called before anything asks for a password. Being prompted for root and then
// told the string was mistyped is a bad trade, and the check costs nothing.
func checkInvite(raw string) (invite.Invite, error) {
	inv, err := invite.Parse(raw)
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
	if err := bringUp(ctx, path); err != nil {
		return err
	}
	installDieAlias()
	linkCLIQuietly()
	return nil
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
		fmt.Println("Up. It stays up — after a restart too — until 'makima down'.")
		fmt.Println()
	}
	return status([]string{"-config", path})
}

// inviteCmd prints a fresh invite for the next machine.
func inviteCmd(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	advertise := fs.String("advertise", "", "where the joining machine reaches this one: a host, host:port, or full URL")
	quiet := fs.Bool("q", false, "print only the pasteable invite, for another program to read")
	asJSON := fs.Bool("json", false, "print both forms as JSON, for the app")
	if err := fs.Parse(args); err != nil {
		return err
	}

	admin, ok := control.DialAdmin(serverSocket())
	if !ok {
		return errors.New("this device does not hold the network — run 'makima invite' on the one that started it")
	}

	serverKey, err := admin.ServerKey()
	if err != nil {
		return err
	}

	reachable := *advertise
	if reachable == "" {
		reachable = guessReachableAddr()
	}

	inv, err := mintInvite(admin, controlURL(reachable), serverKey)
	if err != nil {
		return err
	}
	words, err := mintWords(admin, controlURL(reachable))
	if err != nil {
		return err
	}

	if *quiet {
		fmt.Println(inv)
		return nil
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"words": words, "invite": inv})
	}

	printInvite(words, inv)
	fmt.Printf("\nGood for one device, for %s.\n", inviteTTL)
	warnIfUnreachable(reachable)
	return nil
}

// printInvite shows both forms of an invite: the words to type, and the
// string to paste.
func printInvite(words, inv string) {
	fmt.Println("On the device you are adding, open makima, choose Join a network, and type:")
	fmt.Println()
	fmt.Printf("  %s\n", words)
	fmt.Println()
	fmt.Println("Or paste this there, or into a terminal:")
	fmt.Printf("  makima join %s\n", inv)
}

// mintWords mints a second credential for the same machine, given as words.
//
// A separate credential from the mk1_ one, so that whichever form is used,
// the other stops working with it — an invite is for one machine.
func mintWords(admin *control.AdminClient, serverURL string) (string, error) {
	secret, err := invite.NewSecret()
	if err != nil {
		return "", err
	}
	if _, err := admin.MintInviteKey(invite.AuthKey(secret), invite.Handle(secret), invite.MACKey(secret), inviteTTL); err != nil {
		return "", fmt.Errorf("mint a credential: %w", err)
	}
	return invite.EncodeWords(serverURL, secret)
}

// downCmd stops the tunnel and puts the machine back the way it was.
func downCmd(args []string) error {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	all := fs.Bool("all", false, "also stop the network's server, if this machine holds it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := mustBeRoot(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Stop is called whether or not the daemon is answering: one that is
	// registered with launchd or systemd and merely not running at this
	// moment would otherwise be started again at the next boot, and "down"
	// has to mean down.
	d := daemonFor(*path)
	was := d.Running()
	if err := d.Stop(ctx, stopWait); err != nil {
		return err
	}
	if was {
		fmt.Println("Down, and staying down across restarts until 'makima up'. Interface, routes, resolver and firewall rule put back.")
	} else {
		fmt.Println("Already down.")
	}

	if *all {
		for _, extra := range []supervise.Daemon{controlDaemon(), relayDaemon()} {
			was := extra.Running()
			if err := extra.Stop(ctx, stopWait); err != nil {
				return err
			}
			if was && extra.Name == "makima-server" {
				fmt.Println("The network's server is stopped — no device can join or leave until it is back.")
			}
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
		return fmt.Errorf("this machine is already on a network — 'makima down' first, or remove %s to start over", path)
	}

	// Words carry no server key. Fetch one, and refuse it unless the server
	// can vouch for it under the words — see invite.EncodeWords for why that
	// is as good as having carried it.
	if handle, macKey, ok := inv.Verifier(); ok && inv.ServerKey.IsZero() {
		k, err := control.FetchServerKeyVerified(ctx, inv.Server, handle, macKey)
		if err != nil {
			return err
		}
		inv.ServerKey = k
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

	fmt.Fprintln(os.Stderr, "This needs root — asking sudo.")

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
	fmt.Printf("  ⚠ This network only works from inside this building's network.\n\n")
	fmt.Printf("    %s is a private address. A machine somewhere else cannot reach it, so\n", addr)
	fmt.Println("    'makima join' will fail from anywhere but here — a laptop has to be on this")
	fmt.Println("    network to be added, and once added it can only find its way back home")
	fmt.Println("    through a relay.")
	fmt.Println()
	fmt.Println("    Two ways out. Run 'makima up' on a machine with a public address instead —")
	fmt.Println("    any cheap VPS — and join this one to that; it becomes the relay too.")
	fmt.Println()
	fmt.Println("    Or, if something already carries traffic into this network for you — a")
	fmt.Println("    reverse proxy, a Cloudflare tunnel, a port forward — point it at port 8080")
	fmt.Println("    here and re-run with the name it answers on:")
	fmt.Println()
	fmt.Println("      makima up -advertise https://makima.example.dev")
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

	// Prefer the far end's built-in server when it has one. Probed rather
	// than advertised because it has to work in every mode — a serverless
	// pairing carries no service list, and a peer that switched its server on
	// a minute ago has not re-registered anywhere.
	var extra []string
	if builtInSSH(host) {
		extra = []string{"-p", strconv.Itoa(sshd.DefaultPort)}
	}

	if user != "" {
		host = user + "@" + host
	}

	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return errors.New("no ssh client on this machine")
	}

	args = append(append(extra, host), rest...)
	cmd := exec.Command(ssh, args...)
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

// builtInSSH reports whether a machine is running makima's own SSH server.
//
// One short dial. The alternative — asking the control plane what a peer
// advertises — is unavailable in exactly the cases that matter most: a
// serverless pairing carries no service list at all, and a peer that switched
// its server on a moment ago has not told anyone yet.
func builtInSSH(host string) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(sshd.DefaultPort)), 700*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
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
		return errors.New("paste the invite, or type its words: makima join mk1_...  (get one with 'makima invite' on the device that started the network)")
	}
	if strings.HasPrefix(args[0], "-") {
		return joinNode(args)
	}

	// The invite is every leading argument that is not a flag: one pasted
	// string, or fifteen typed words.
	var raw []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		raw = append(raw, args[0])
		args = args[1:]
	}

	fs := flag.NewFlagSet("join", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	name := fs.String("name", "", "this machine's name on the mesh (defaults to the hostname)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Before sudo, not after: being asked for a password and then told the
	// invite was mistyped is the wrong order to find that out in.
	inv, err := checkInvite(strings.Join(raw, " "))
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

// relayDaemon is the fallback path, run on the machine holding the mesh.
func relayDaemon() supervise.Daemon {
	return supervise.Daemon{
		Name: "makima-relay",
		Args: []string{"serve", "-state", relayStatePath},
		// No Unix socket: the port it forwards on is the only evidence it is
		// up, and without a probe every `makima up` would start another one.
		TCPAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(relay.DefaultPort)),
		PIDFile: filepath.Join(runDir, "makima-relay.pid"),
		LogFile: filepath.Join(logDir, "makima-relay.log"),
		Service: supervise.Service{
			Label:       "sh.makima.relay",
			Unit:        "makima-relay",
			Description: "makima: the relay",
		},
	}
}

// startRelayIfPublic turns the coordination machine into a relay as well.
//
// Two machines behind different NATs cannot dial each other, and the way they
// meet is a relay — which has to be somewhere both can reach, which means a
// public address. The machine holding the mesh already needs one for anything
// to work from outside the house, so it is exactly the machine that can be a
// relay, and asking somebody to set up a second one would be asking them to
// solve a problem they have already solved.
//
// Skipped on a private address, where it would be a listener nothing could
// ever connect to.
func startRelayIfPublic(ctx context.Context, admin *control.AdminClient, addr string) {
	ip, err := netip.ParseAddr(addr)
	if err != nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return
	}

	id, err := relay.LoadIdentity(relayStatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: no relay here: %v\n", err)
		return
	}

	if err := relayDaemon().Start(ctx, startWait); err != nil {
		fmt.Fprintf(os.Stderr, "note: no relay here: %v\n", err)
		return
	}

	url := net.JoinHostPort(addr, strconv.Itoa(relay.DefaultPort))
	if err := admin.AddRelay(url, id.PrivateKey.Public()); err != nil {
		fmt.Fprintf(os.Stderr, "note: the relay is running but the mesh was not told about it: %v\n", err)
		return
	}

	fmt.Printf("Relaying on %s too, so machines that cannot reach each other directly still can.\n", url)
	fmt.Printf("Open TCP %d on this host's firewall if it has one.\n", relay.DefaultPort)
}

// controlURL turns what somebody passed to -advertise into a URL a joining
// machine can use.
//
// Three forms, because there are three real situations. A bare address is the
// common one and gets the default port. A host:port is a moved listener. And a
// full URL is the case that matters most for somebody who already self-hosts:
// if a reverse proxy or a Cloudflare tunnel is already carrying traffic into
// the house for some other service, the coordination plane can ride the same
// path — and then it is on 443 behind a name, not on 8080 behind an address.
func controlURL(advertise string) string {
	s := strings.TrimSpace(advertise)
	s = strings.TrimRight(s, "/")

	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s
	}
	// An IPv6 literal has colons of its own, so "has a colon" is not the same
	// question as "has a port".
	if _, _, err := net.SplitHostPort(s); err == nil {
		return "http://" + s
	}
	return "http://" + net.JoinHostPort(s, "8080")
}
