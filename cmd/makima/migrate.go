package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/invite"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/migrate"
	"github.com/justin06lee/makima/internal/netcfg"
)

// migrateCmd is `makima migrate`: everything on Tailscale, onto makima.
//
// With no arguments it is the whole thing, in a terminal — scan, ask which
// machine holds the network, confirm, go. The app drives the same steps through
// `scan` and `run`. The rest are the halves that run as root on each machine,
// which the migration calls; nobody needs to type them.
func migrateCmd(args []string) error {
	if len(args) == 0 {
		return migrateInteractive()
	}
	switch args[0] {
	case "detect":
		return migrateDetect(args[1:])
	case "scan":
		return migrateScan(args[1:])
	case "run":
		return migrateRun(args[1:])
	case "host":
		return migrateHost(args[1:])
	case "join":
		return migrateJoin(args[1:])
	case "probe":
		return migrateProbe(args[1:])
	case "retire":
		return migrateRetire(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stderr, migrateUsage)
		return nil
	}
	return fmt.Errorf("unknown migrate step %q\n\n%s", args[0], migrateUsage)
}

const migrateUsage = `makima migrate — move every machine on your tailnet to makima

  makima migrate          look at the tailnet, pick the machine that holds the
                          network, and move everything — asks before changing anything

The app does the same from its Move from Tailscale button. The steps it is made of:

  detect                  is Tailscale here, and running?
  scan                    look at every machine over Tailscale SSH; change nothing
  run                     carry out a choice made from a scan
  host | join             start the network here, or join it — beside Tailscale,
                          which keeps running
  retire                  remove Tailscale from this machine; refused unless
                          makima is up here
  probe URL               can this machine reach a server without Tailscale?
`

// --- detect -------------------------------------------------------------

type detection struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Tailnet   string `json:"tailnet,omitempty"`
	Self      string `json:"self,omitempty"`
	Peers     int    `json:"peers"`
	Online    int    `json:"online"`
	Error     string `json:"error,omitempty"`
}

func detect(ctx context.Context) detection {
	tn, err := migrate.Status(ctx)
	if errors.Is(err, migrate.ErrNoTailscale) {
		return detection{}
	}
	if err != nil {
		return detection{Installed: true, Error: err.Error()}
	}
	d := detection{Installed: true, Running: tn.Running(), Tailnet: tn.Name, Self: tn.Self.Name, Peers: len(tn.Peers)}
	for _, p := range tn.Peers {
		if p.Online {
			d.Online++
		}
	}
	return d
}

func migrateDetect(args []string) error {
	fs := flag.NewFlagSet("migrate detect", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON, for the app")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d := detect(context.Background())
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(d)
	}
	switch {
	case !d.Installed:
		fmt.Println("Tailscale is not installed here.")
	case !d.Running:
		fmt.Println("Tailscale is installed here, but not connected.")
	default:
		fmt.Printf("On the tailnet %s with %d other machine(s), %d online.\n", d.Tailnet, d.Peers, d.Online)
	}
	return nil
}

// --- scan ---------------------------------------------------------------

// events writes one JSON object per line, from any goroutine.
type events struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (e *events) send(v any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.enc.Encode(v)
}

func scanTailnet(ctx context.Context, emit func(migrate.Event)) (migrate.Plan, error) {
	tn, err := migrate.Status(ctx)
	if err != nil {
		return migrate.Plan{}, err
	}
	if !tn.Running() {
		return migrate.Plan{}, fmt.Errorf("Tailscale is not connected here (%s) — connect it first; it is how the other machines are reached", strings.ToLower(tn.State))
	}
	ssh, err := migrate.NewSSH()
	if err != nil {
		return migrate.Plan{}, err
	}
	defer ssh.Close()
	return migrate.Scan(ctx, tn, migrate.Scanner{SSH: ssh, Emit: emit, Version: version}), nil
}

func migrateScan(args []string) error {
	fs := flag.NewFlagSet("migrate scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "stream JSON events, for the app")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	if *asJSON {
		out := &events{enc: json.NewEncoder(os.Stdout)}
		plan, err := scanTailnet(ctx, func(e migrate.Event) { out.send(e) })
		if err != nil {
			out.send(migrate.Event{Type: "error", Detail: err.Error()})
			return nil
		}
		out.send(migrate.Event{Type: "plan", Plan: &plan})
		return nil
	}
	plan, err := scanTailnet(ctx, printAuth)
	if err != nil {
		return err
	}
	printPlan(plan)
	return nil
}

func printAuth(e migrate.Event) {
	if e.Type == "auth" {
		fmt.Fprintf(os.Stderr, "  Tailscale SSH wants this approved in a browser: %s\n", e.URL)
	}
}

func printPlan(p migrate.Plan) {
	fmt.Printf("Tailnet %s\n\n", p.Tailnet)
	for i, c := range p.Sorted() {
		mark := "  "
		if c.ID == p.Controller {
			mark = "★ "
		}
		state := "can move"
		if !c.Eligible {
			state = "stays"
		}
		fmt.Printf("%s%2d  %-22s %-8s %-9s %s\n", mark, i+1, c.Name, c.OS, state, firstNonEmpty(c.Why, c.Pitch))
	}
	if p.Advice != "" {
		fmt.Printf("\n%s\n", p.Advice)
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- run ----------------------------------------------------------------

func migrateRun(args []string) error {
	fs := flag.NewFlagSet("migrate run", flag.ExitOnError)
	app := fs.Bool("app", false, "take the choice and answers on stdin and stream JSON, for the app")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*app {
		return errors.New("run the whole migration with just 'makima migrate'")
	}

	in := bufio.NewReader(os.Stdin)
	line, err := in.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return fmt.Errorf("read the choice: %w", err)
	}
	var ch migrate.Choice
	if err := json.Unmarshal(line, &ch); err != nil {
		return fmt.Errorf("read the choice: %w", err)
	}

	out := &events{enc: json.NewEncoder(os.Stdout)}
	rpc := newAppRPC(out, in)
	runChoice(context.Background(), ch, func(e migrate.Event) { out.send(e) }, rpc.elevate)
	return nil
}

// runChoice carries out a choice, with root steps on this machine done by
// elevate.
func runChoice(ctx context.Context, ch migrate.Choice, emit func(migrate.Event), elevate func(context.Context, migrate.Action) (string, error)) migrate.Result {
	ssh, err := migrate.NewSSH()
	if err != nil {
		res := migrate.Result{Error: err.Error()}
		emit(migrate.Event{Type: "result", Result: &res})
		return res
	}
	defer ssh.Close()
	r := &migrate.Runner{
		SSH:     ssh,
		Emit:    emit,
		Version: version,
		Elevate: elevate,
		Probe:   probeServer,
		Peers:   meshPeers,
		Pubkeys: ownPubkeys,
	}
	return r.Run(ctx, ch)
}

// appRPC asks the app to run root steps. The app owns the password prompt —
// and the remembered answer to it — so a step is sent up as an event and the
// app writes back what came of it.
type appRPC struct {
	out *events

	mu      sync.Mutex
	next    int
	waiting map[int]chan appReply
}

type appReply struct {
	ID     int    `json:"id"`
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

func newAppRPC(out *events, in *bufio.Reader) *appRPC {
	r := &appRPC{out: out, waiting: map[int]chan appReply{}}
	go func() {
		sc := bufio.NewScanner(in)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			var rep appReply
			if json.Unmarshal(sc.Bytes(), &rep) != nil {
				continue
			}
			r.mu.Lock()
			ch, ok := r.waiting[rep.ID]
			delete(r.waiting, rep.ID)
			r.mu.Unlock()
			if ok {
				ch <- rep
			}
		}
		// The app went away. Nothing more can be asked of it.
		r.mu.Lock()
		for id, ch := range r.waiting {
			ch <- appReply{ID: id, Output: "the app closed"}
			delete(r.waiting, id)
		}
		r.mu.Unlock()
	}()
	return r
}

func (r *appRPC) elevate(ctx context.Context, a migrate.Action) (string, error) {
	r.mu.Lock()
	r.next++
	id := r.next
	ch := make(chan appReply, 1)
	r.waiting[id] = ch
	r.mu.Unlock()

	r.out.send(map[string]any{"type": "elevate", "id": id, "action": a})
	select {
	case rep := <-ch:
		if !rep.OK {
			if rep.Output == "cancelled" {
				return "", errors.New("the password prompt was cancelled")
			}
			return rep.Output, errors.New(rep.Output)
		}
		return rep.Output, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// sudoElevate runs a root step through sudo, at a terminal.
func sudoElevate(ctx context.Context, a migrate.Action) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "sudo", append([]string{self}, a.Args()...)...)
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	out, err := cmd.Output()
	return string(out), err
}

// meshPeers is this machine's view of the makima network, by name. Read over
// the daemon's own socket, or — for the person who is not root, which is who
// runs the migration — the read-only one it keeps for them.
func meshPeers() map[string]migrate.MeshPeer {
	c, err := dialDaemon(conf.DefaultPath)
	if err != nil {
		return nil
	}
	st, err := c.Status()
	if err != nil {
		return nil
	}
	m := map[string]migrate.MeshPeer{}
	for _, p := range st.Peers {
		m[p.Name] = migrate.MeshPeer{Address: p.Address.String(), Online: p.Online, Direct: p.Direct}
	}
	return m
}

// ownPubkeys are the SSH public keys of whoever is running this, from their
// agent and their ~/.ssh — the keys every machine is given, so that ssh
// reaches it without Tailscale.
func ownPubkeys() string {
	seen := map[string]bool{}
	var keys []string
	add := func(text string) {
		for _, l := range strings.Split(text, "\n") {
			l = strings.TrimSpace(l)
			f := strings.Fields(l)
			if len(f) < 2 || seen[f[1]] {
				continue
			}
			if strings.HasPrefix(f[0], "ssh-") || strings.HasPrefix(f[0], "ecdsa-") || strings.HasPrefix(f[0], "sk-") {
				seen[f[1]] = true
				keys = append(keys, l)
			}
		}
	}
	if out, err := exec.Command("ssh-add", "-L").Output(); err == nil {
		add(string(out))
	}
	if home, err := os.UserHomeDir(); err == nil {
		matches, _ := filepath.Glob(filepath.Join(home, ".ssh", "*.pub"))
		for _, m := range matches {
			if b, err := os.ReadFile(m); err == nil {
				add(string(b))
			}
		}
	}
	return strings.Join(keys, "\n")
}

// --- probe --------------------------------------------------------------

func migrateProbe(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: makima migrate probe URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := probeServer(ctx, args[0]); err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}

// probeServer checks that a network's server answers, and that it does so by
// a route that will still be there once Tailscale is gone.
func probeServer(ctx context.Context, server string) error {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not a server address", server)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = map[string]string{"https": "443"}[u.Scheme]
		if port == "" {
			port = "80"
		}
	}
	if migrate.IsTailscaleHost(host) {
		return fmt.Errorf("%s is a Tailscale address", host)
	}
	// Which of this machine's addresses would carry the traffic. A Tailscale
	// one means the route is a subnet router or an exit node — both gone the
	// moment Tailscale is.
	if c, err := net.Dial("udp", net.JoinHostPort(host, port)); err == nil {
		local := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
		c.Close()
		if migrate.IsTailscaleAddr(local) {
			return fmt.Errorf("the only route to %s here goes through Tailscale", host)
		}
	}
	// A TCP connection first, because how it fails says what is wrong: a
	// refusal is nothing listening, silence is a firewall.
	d := net.Dialer{Timeout: 6 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("nothing is listening at %s:%s", host, port)
	case err != nil:
		return fmt.Errorf("%s does not answer on TCP %s — its firewall is probably dropping it; allow TCP %s there", host, port, port)
	}
	c.Close()
	if _, err := control.FetchServerKey(ctx, server); err != nil {
		return fmt.Errorf("%s answers, but not as a makima server", net.JoinHostPort(host, port))
	}
	return nil
}

// --- host ---------------------------------------------------------------

// migrateHost starts the network on this machine — or finds it running here —
// and mints an invite for every machine about to join. Tailscale is not
// touched.
func migrateHost(args []string) error {
	fs := flag.NewFlagSet("migrate host", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	advertise := fs.String("advertise", "", "where the other machines reach this one")
	name := fs.String("name", "", "this machine's name on the network")
	count := fs.Int("invites", 0, "how many invites to mint")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	fromStdin := fs.Bool("stdin", false, "read SSH keys as JSON on stdin")
	sshUser := fs.String("ssh-user", "", "turn on makima's SSH server for this account, with the keys given on stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name != "" && !migrate.ValidName(*name) {
		return fmt.Errorf("%q is not a name makima can use", *name)
	}
	if *count < 0 || *count > 250 {
		return errors.New("-invites must be between 0 and 250")
	}
	if err := migrate.CheckAdvertise(*advertise); err != nil {
		return err
	}
	in, err := readInput(*fromStdin)
	if err != nil {
		return err
	}
	if err := mustBeRoot(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Everything bootstrap and bringUp print goes to stderr, so the one line
	// on stdout is the answer.
	stdout := os.Stdout
	os.Stdout = os.Stderr
	server, err := holdNetwork(ctx, *path, *name, *advertise)
	if err == nil && *sshUser != "" && in.SSHKeys != "" {
		if serr := enableOwnSSH(*path, in.SSHKeys, *sshUser); serr != nil {
			fmt.Fprintf(os.Stderr, "note: makima's SSH server did not start: %v\n", serr)
		}
	}
	os.Stdout = stdout
	if err != nil {
		return err
	}

	admin, ok := control.DialAdmin(serverSocket())
	if !ok {
		return errors.New("the network's server is not answering")
	}
	serverKey, err := admin.ServerKey()
	if err != nil {
		return err
	}
	res := migrate.HostResult{Server: server, Name: *name, Invites: []string{}}
	for i := 0; i < *count; i++ {
		inv, err := mintInvite(admin, server, serverKey)
		if err != nil {
			return err
		}
		res.Invites = append(res.Invites, inv)
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(res)
	}
	fmt.Printf("Holding the network at %s.\n", server)
	for _, inv := range res.Invites {
		fmt.Printf("  makima join %s\n", inv)
	}
	return nil
}

// holdNetwork makes sure this machine holds a network, running the makima
// just installed, and is on it — and says where it is.
//
// The machine was chosen to hold the network, so whatever makima network it
// was on before gives way: one from an older makima, on Tailscale's range,
// starts over; one held somewhere else is left. A network it already holds on
// makima's own range is kept, with everything on it.
func holdNetwork(ctx context.Context, path, name, advertise string) (string, error) {
	f, err := conf.Load(path)
	if err == nil {
		switch {
		case onLegacyRange(f) || serverStateOnLegacyRange(serverStatePath):
			fmt.Fprintf(os.Stderr, "This machine is on a network from an older makima, in 100.64.0.0/10 — Tailscale's range, which cannot run beside Tailscale. Starting it over in %s.\n", netcfg.MeshRange)
			if err := leaveNetwork(ctx, path, true); err != nil {
				return "", err
			}
			f = nil
		case !f.Managed():
			return "", errors.New("this machine is on a makima network with no server — it cannot hold one as well")
		case !holdsNetworkHere():
			fmt.Fprintf(os.Stderr, "This machine is on the network held at %s. It leaves that one to hold this.\n", f.LoginServer)
			if err := leaveNetwork(ctx, path, false); err != nil {
				return "", err
			}
			f = nil
		}
	} else if serverStateOnLegacyRange(serverStatePath) {
		if err := leaveNetwork(ctx, path, true); err != nil {
			return "", err
		}
	}
	if f == nil {
		if err := bootstrap(ctx, path, name, advertise); err != nil {
			return "", err
		}
		return controlURL(advertise), nil
	}

	if err := migrate.CheckAdvertise(f.LoginServer); err != nil {
		return "", fmt.Errorf("the network this machine holds is reached at %s, which stops working with Tailscale: %w", f.LoginServer, err)
	}
	// Restarted, both of them, so they run the makima that was just put here
	// rather than whichever one was running.
	server := controlDaemon()
	if err := server.Stop(ctx, stopWait); err != nil {
		return "", err
	}
	if err := server.Start(ctx, startWait); err != nil {
		return "", err
	}
	if !holdsOwn(f) {
		return "", fmt.Errorf("this machine is on the network held at %s, not the one its own server holds", f.LoginServer)
	}
	openServerPort(serverPort())
	if err := daemonFor(path).Stop(ctx, stopWait); err != nil {
		return "", err
	}
	if err := bringUp(ctx, path); err != nil {
		return "", err
	}
	return f.LoginServer, nil
}

// holdsOwn says whether the server on this machine is the one this node
// belongs to.
func holdsOwn(f *conf.File) bool {
	admin, ok := control.DialAdmin(serverSocket())
	if !ok {
		return false
	}
	k, err := admin.ServerKey()
	return err == nil && k == f.ServerKey
}

// holdsNetworkHere says whether a network's server lives on this machine.
func holdsNetworkHere() bool {
	_, err := os.Stat(serverStatePath)
	return err == nil
}

// onLegacyRange says whether this node's address is from 100.64.0.0/10, where
// makima allocated before it had a range of its own.
func onLegacyRange(f *conf.File) bool {
	a, err := f.Self.Addr()
	return err == nil && netcfg.LegacyMeshRange.Contains(a)
}

// serverStateOnLegacyRange says whether the server whose state is at path
// hands out addresses from 100.64.0.0/10.
func serverStateOnLegacyRange(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var st struct {
		Prefix netip.Prefix `json:"prefix"`
	}
	if json.Unmarshal(b, &st) != nil || !st.Prefix.IsValid() {
		return false
	}
	return netcfg.LegacyMeshRange.Contains(st.Prefix.Addr())
}

// leaveNetwork takes this machine off the network it is on, keeping nothing of
// it: the node's identity goes, and with withServer the server's state too, so
// what starts next is new.
func leaveNetwork(ctx context.Context, path string, withServer bool) error {
	if err := daemonFor(path).Stop(ctx, stopWait); err != nil {
		return err
	}
	if withServer {
		if err := controlDaemon().Stop(ctx, stopWait); err != nil {
			return err
		}
		if err := os.Remove(serverStatePath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// --- join ---------------------------------------------------------------

// migrateJoin puts this machine on the network, leaving Tailscale running.
//
// A machine already on it is restarted onto the makima just installed. One on
// another network leaves that one — it was chosen to move — unless it holds
// that network itself, which would strand everything on it.
func migrateJoin(args []string) error {
	fs := flag.NewFlagSet("migrate join", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	name := fs.String("name", "", "this machine's name on the network")
	fromStdin := fs.Bool("stdin", false, "read the invite and SSH keys as JSON on stdin")
	sshUser := fs.String("ssh-user", "", "turn on makima's SSH server for this account, with the keys given on stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name != "" && !migrate.ValidName(*name) {
		return fmt.Errorf("%q is not a name makima can use", *name)
	}
	in, err := readInput(*fromStdin)
	if err != nil {
		return err
	}
	if in.Invite == "" {
		in.Invite = strings.Join(fs.Args(), " ")
	}
	inv, err := checkInvite(in.Invite)
	if err != nil {
		return err
	}
	if err := mustBeRoot(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if f, err := conf.Load(*path); err == nil {
		switch joinDecision(f, inv, holdsNetworkHere(), serverStateOnLegacyRange(serverStatePath)) {
		case joinRestart:
			if err := daemonFor(*path).Stop(ctx, stopWait); err != nil {
				return err
			}
			if err := bringUp(ctx, *path); err != nil {
				return err
			}
			return sshAfterJoin(*path, in, *sshUser)
		case joinRefuse:
			return fmt.Errorf("this machine holds the makima network at %s — it can only move by being chosen to hold this one", f.LoginServer)
		case joinLeave:
			fmt.Fprintf(os.Stderr, "Leaving the network at %s for this one.\n", f.LoginServer)
			if err := leaveNetwork(ctx, *path, holdsNetworkHere()); err != nil {
				return err
			}
		}
	}
	if err := joinWith(ctx, *path, inv, *name); err != nil {
		return err
	}
	return sshAfterJoin(*path, in, *sshUser)
}

type joinChoice int

const (
	joinRestart joinChoice = iota // already on this network
	joinLeave                     // on another one, which it leaves
	joinRefuse                    // holds another one
)

// joinDecision says what a machine already on a network does with an invite
// to one: the same network is restarted; another is left, unless this machine
// holds it — then it stays, because leaving would strand every machine on it.
// A network from an older makima, on Tailscale's range, is always left, its
// server with it: it cannot run beside Tailscale, and the move is replacing it.
func joinDecision(f *conf.File, inv invite.Invite, holds, holdsLegacy bool) joinChoice {
	same := f.LoginServer == strings.TrimRight(inv.Server, "/") &&
		(inv.ServerKey == (key.Public{}) || inv.ServerKey == f.ServerKey)
	switch {
	case same && !onLegacyRange(f):
		return joinRestart
	case holds && !holdsLegacy && !onLegacyRange(f):
		return joinRefuse
	}
	return joinLeave
}

// sshAfterJoin switches on makima's SSH server, where the move asked for it.
func sshAfterJoin(path string, in migrate.Input, user string) error {
	if user == "" || in.SSHKeys == "" {
		return nil
	}
	if err := enableOwnSSH(path, in.SSHKeys, user); err != nil {
		fmt.Fprintf(os.Stderr, "note: makima's SSH server did not start: %v\n", err)
	}
	return nil
}

// readInput reads what another machine sent on stdin, when asked to.
func readInput(fromStdin bool) (migrate.Input, error) {
	var in migrate.Input
	if !fromStdin {
		return in, nil
	}
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if strings.TrimSpace(string(b)) == "" {
		return in, nil
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return in, fmt.Errorf("read the input: %w", err)
	}
	return in, nil
}

// enableOwnSSH switches on makima's SSH server with the keys the migration
// brought, for a machine that was only reachable by Tailscale SSH.
func enableOwnSSH(path, keys, user string) error {
	file := filepath.Join(filepath.Dir(path), "authorized_keys")
	lines := strings.Split(strings.TrimSpace(keys), "\n")
	sort.Strings(lines)
	if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	c, err := localapi.Dial(localapi.SocketPath(path))
	if err != nil {
		return err
	}
	return c.SetSSH(true, []string{file}, user)
}

// --- retire -------------------------------------------------------------

// migrateRetire removes Tailscale from this machine: the last step of a move,
// run over makima once this machine has been reached through it.
//
// It refuses unless makima is up here and on a network. Taking Tailscale off a
// machine makima is not carrying would leave it reachable by neither.
func migrateRetire(args []string) error {
	fs := flag.NewFlagSet("migrate retire", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return migrate.ErrNotRoot
	}
	c, err := localapi.Dial(localapi.SocketPath(*path))
	if err != nil {
		return errors.New("makima is not running here, so Tailscale stays")
	}
	st, err := c.Status()
	if err != nil || !st.Managed {
		return errors.New("makima is not on a network here, so Tailscale stays")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	os.Setenv("PATH", os.Getenv("PATH")+":/usr/local/bin:/usr/sbin:/sbin:/opt/homebrew/bin")
	var res migrate.Retired
	if ts, found := migrate.FindTailscale(ctx, migrate.ThisHost()); found {
		res.Notes, _ = ts.Remove(ctx)
		res.Removed = true
	}
	return json.NewEncoder(os.Stdout).Encode(res)
}

// --- the terminal version -----------------------------------------------

func migrateInteractive() error {
	ctx := context.Background()
	fmt.Println("Looking at your tailnet over Tailscale. Nothing changes until you say so.")
	fmt.Println()
	plan, err := scanTailnet(ctx, printAuth)
	if err != nil {
		return err
	}
	printPlan(plan)

	sorted := plan.Sorted()
	var movable []migrate.Candidate
	for _, c := range sorted {
		if c.Eligible {
			movable = append(movable, c)
		}
	}
	if len(movable) == 0 {
		return errors.New("no machine here can be moved")
	}

	in := bufio.NewReader(os.Stdin)
	rec := 1
	fmt.Printf("\nWhich machine should be the Control Devil — the one holding the network? [%d] ", rec)
	pick := rec
	if line, _ := in.ReadString('\n'); strings.TrimSpace(line) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || n < 1 || n > len(sorted) || !sorted[n-1].Eligible {
			return errors.New("that is not one of the machines that can move")
		}
		pick = n
	}
	ctrl := sorted[pick-1]

	ch := migrate.Choice{Plan: plan, Controller: ctrl.ID, Passwords: map[string]string{}}
	for _, c := range movable {
		ch.Selected = append(ch.Selected, c.ID)
		if c.NeedsPassword {
			pw, err := readPassword(in, fmt.Sprintf("sudo password for %s on %s: ", c.Facts.User, c.Name))
			if err != nil {
				return err
			}
			ch.Passwords[c.ID] = pw
		}
	}
	fmt.Printf("It will be reached at %s. Enter to keep, or type another address: ", ctrl.Reach)
	if line, _ := in.ReadString('\n'); strings.TrimSpace(line) != "" {
		ch.Advertise = strings.TrimSpace(line)
	}
	fmt.Print("Uninstall Tailscale from each machine once it has been reached over makima? [Y/n] ")
	line, _ := in.ReadString('\n')
	ch.Remove = !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "n")
	fmt.Printf("Move %d machine(s) to makima, held by %s? [y/N] ", len(movable), ctrl.Name)
	line, _ = in.ReadString('\n')
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
		return errors.New("nothing was changed")
	}
	fmt.Println()

	names := map[string]string{}
	for _, c := range plan.Machines {
		names[c.ID] = c.Name
	}
	res := runChoice(ctx, ch, func(e migrate.Event) {
		switch e.Type {
		case "step":
			if e.Detail != "" || e.State != "running" {
				fmt.Printf("  %-20s %-8s %s %s\n", names[e.Machine], e.Step, e.State, e.Detail)
			}
		case "auth":
			fmt.Printf("  %-20s approve in a browser: %s\n", names[e.Machine], e.URL)
		}
	}, sudoElevate)

	fmt.Println()
	for _, m := range res.Machines {
		fmt.Printf("  %-20s %-7s %s\n", m.Name, m.Outcome, m.Detail)
		for _, n := range m.Notes {
			fmt.Printf("  %-20s %-7s note: %s\n", "", "", n)
		}
	}
	if res.Error != "" {
		return errors.New(res.Error)
	}
	return nil
}

// readPassword reads a line with the terminal's echo off.
func readPassword(in *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	_ = off.Run()
	defer func() {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		_ = on.Run()
		fmt.Fprintln(os.Stderr)
	}()
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
