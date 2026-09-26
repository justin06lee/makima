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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/hostaddr"
	"github.com/justin06lee/makima/internal/invite"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/relay"
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
// after a reboot.
//
// It carries no owner. Who this machine belongs to is written in the config by
// recordOwner instead, because a service definition is the wrong place to keep
// it: `makima owner` would then be undone by the next reboot, and a machine
// set up over SSH as root — where nothing in the environment says who it is
// for — would have nothing written anywhere.
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
	return d
}

// recordOwner writes down whose machine this is, before the daemon starts.
//
// The daemon can work it out for itself from sudo, from polkit, or from who is
// logged in at the screen — but only when one of those is true at the moment
// it starts, and for a service launchd or systemd brings up at boot, none of
// them is. This runs where the answer is still known: inside the `sudo makima
// up` that a person typed.
//
// Best-effort throughout. Not knowing who ran this is normal on a machine
// administered as root, and it is the daemon's job to fall back; failing to
// bring up a tunnel over it would be absurd.
func recordOwner(path string) {
	u := invokerFromEnv()
	if u == nil || u.Username == "" {
		return
	}
	f, err := conf.Load(path)
	if err != nil || f.Owner == u.Username {
		return
	}
	f.Owner = u.Username
	_ = conf.Save(path, f)
}

// livePort is the port the network's server on this machine answers on:
// the running server's own answer, else what it recorded beside its state,
// else the port a new one would try first. The server decides it
// (control.ListenControl) and everything here asks, so an invite, the
// firewall and the forwarding advice always name the port in use — before,
// `makima up` chose and wrote a port of its own, and running it again after
// an interrupted start picked a new one while the server kept the old.
func livePort(admin *control.AdminClient) int {
	if admin != nil {
		if p, err := admin.ListenPort(); err == nil && p != 0 {
			return p
		}
	}
	if p := control.RecordedPort(serverStatePath); p != 0 {
		return p
	}
	return control.DefaultPort
}

// advertisedPort is the port in an -advertise given as host:port, or zero.
func advertisedPort(advertise string) int {
	s := strings.TrimSpace(advertise)
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return 0
	}
	if _, p, err := net.SplitHostPort(s); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return 0
}

// promisePort writes down the port an -advertise host:port promised the
// other machines, before the new network's server first starts, so that is
// where it listens.
func promisePort(advertise string) error {
	want := advertisedPort(advertise)
	if want == 0 {
		return nil
	}
	if got := control.RecordedPort(serverStatePath); got != 0 && got != want {
		return fmt.Errorf("this machine's network server already listens on %d, not %d", got, want)
	}
	l, err := net.Listen("tcp", ":"+strconv.Itoa(want))
	if err != nil {
		if control.RecordedPort(serverStatePath) == want {
			return nil // our own server, already there
		}
		return fmt.Errorf("port %d is already in use on this machine, so the network cannot be reached at %s — pick another port, or give just the address", want, advertise)
	}
	l.Close()
	return control.RecordPort(serverStatePath, want)
}

// openServerPort lets the other machines through the host firewall to the
// server, where makima can do that properly, and says what to do where it
// cannot. A server nobody can reach looks exactly like one that is down.
func openServerPort(port int) {
	via, err := netcfg.OpenPort("tcp", port)
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "note: %v\n", err)
	case via != "":
		fmt.Printf("Opened TCP %d in %s, so the other machines can reach the server.\n", port, via)
	}
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

	if err := promisePort(advertise); err != nil {
		return err
	}

	server := controlDaemon()
	if err := server.Start(ctx, startWait); err != nil {
		return err
	}

	admin, ok := control.DialAdmin(serverSocket())
	if !ok {
		return fmt.Errorf("the network's server started but is not answering on %s", serverSocket())
	}

	// The port the server took, not one decided here: a server already
	// running from an interrupted start keeps the one it has.
	port := livePort(admin)
	if port != control.DefaultPort && advertisedPort(advertise) == 0 {
		fmt.Printf("Port %d is taken here, so the network's server listens on %d.\n", control.DefaultPort, port)
	}
	openServerPort(port)

	serverKey, err := admin.ServerKey()
	if err != nil {
		return fmt.Errorf("read the mesh's public key: %w", err)
	}

	reachable := advertise
	if reachable == "" {
		reachable = guessReachableAddr()
	}
	serverURL := controlURLOn(reachable, port)

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

	decoded, err := checkInvite(inv)
	if err != nil {
		return err
	}
	if err := joinWith(ctx, path, decoded, name); err != nil {
		return err
	}

	fmt.Println()
	printInvite(words, inv)
	warnIfUnreachable(reachable, port)
	linkCLIQuietly()
	offerAlias()
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
	linkCLIQuietly()
	offerAlias()
	return nil
}

// bringUp starts the daemon and prints what the machine can now see.
func bringUp(ctx context.Context, path string) error {
	recordOwner(path)

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

	port := livePort(admin)
	inv, err := mintInvite(admin, controlURLOn(reachable, port), serverKey)
	if err != nil {
		return err
	}
	words, err := mintWords(admin, controlURLOn(reachable, port))
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
	warnIfUnreachable(reachable, port)
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
		Endpoints: hostaddr.LocalEndpoints(listenPort),
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
// the world cannot get to, and what makes it reachable.
//
// The one thing about self-hosting that cannot be automated away: a router
// has to let the traffic in. Everything else — a name that follows the home
// address, every node learning it, the relay riding along — makima does once
// asked. Better said now than discovered in a hotel.
func warnIfUnreachable(addr string, port int) {
	ip, err := netip.ParseAddr(addr)
	if err != nil || !ip.IsPrivate() {
		return
	}
	fmt.Println()
	fmt.Printf("  ⚠ For now, this network only works inside this building.\n\n")
	fmt.Printf("    %s is a private address, so a machine somewhere else cannot reach it.\n", addr)
	fmt.Println("    Machines added here keep working when they leave, but lose track of the")
	fmt.Println("    others until they are back.")
	fmt.Println()
	fmt.Println("    To reach it from anywhere, give it a name and let the traffic in:")
	fmt.Println()
	fmt.Println("      1. get a free name at https://www.duckdns.org, then run here:")
	fmt.Println("           sudo makima-server ddns set -name NAME")
	fmt.Printf("      2. forward TCP %d on your router to this machine — the command above\n", port)
	fmt.Println("         prints exactly what to forward.")
	fmt.Println()
	fmt.Println("    Every machine learns the name on its own, and the relay rides the same port.")
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
	var admin *control.AdminClient
	if a, ok := control.DialAdmin(serverSocket()); ok {
		admin = a
	}
	return controlURLOn(advertise, livePort(admin))
}

// controlURLOn is controlURL with the server's port given rather than read.
func controlURLOn(advertise string, port int) string {
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
	return "http://" + net.JoinHostPort(s, strconv.Itoa(port))
}
