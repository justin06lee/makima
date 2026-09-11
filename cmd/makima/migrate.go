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
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/migrate"
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
	case "cutover":
		return migrateCutover(args[1:])
	case "status":
		b, err := os.ReadFile(migrate.StatePath)
		if err != nil {
			return errors.New("no migration has run on this machine")
		}
		os.Stdout.Write(b)
		return nil
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
  host | join | cutover   the parts run as root on each machine
  probe URL               can this machine reach a server without Tailscale?
  status                  how this machine's switch went
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
	res := runChoice(context.Background(), ch, func(e migrate.Event) { out.send(e) }, rpc.elevate)
	_ = res
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

// meshPeers is this machine's view of the makima network, by name.
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
		m[p.Name] = migrate.MeshPeer{Address: p.Address.String(), Online: p.Online}
	}
	return m
}

// ownPubkeys are the SSH public keys of whoever is running this, from their
// agent and their ~/.ssh, for makima's SSH server on machines that had none.
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
	if _, err := control.FetchServerKey(ctx, server); err != nil {
		return fmt.Errorf("no answer from %s", server)
	}
	return nil
}

// --- host ---------------------------------------------------------------

// migrateHost starts the network on this machine — or finds it already
// running here — and mints an invite for every machine about to join.
func migrateHost(args []string) error {
	fs := flag.NewFlagSet("migrate host", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	advertise := fs.String("advertise", "", "where the other machines reach this one")
	name := fs.String("name", "", "this machine's name on the network")
	count := fs.Int("invites", 0, "how many invites to mint")
	asJSON := fs.Bool("json", false, "print the result as JSON")
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
	if err := mustBeRoot(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Everything bootstrap and bringUp print goes to stderr, so the one line
	// on stdout is the answer.
	stdout := os.Stdout
	os.Stdout = os.Stderr
	server, err := holdNetwork(ctx, *path, *name, *advertise)
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

// holdNetwork makes sure this machine holds a network and is on it, and says
// where it is.
func holdNetwork(ctx context.Context, path, name, advertise string) (string, error) {
	f, err := conf.Load(path)
	if err != nil {
		if err := bootstrap(ctx, path, name, advertise); err != nil {
			return "", err
		}
		return controlURL(advertise), nil
	}
	if !f.Managed() {
		return "", errors.New("this machine is on a makima network with no server — it cannot hold one as well")
	}
	if err := migrate.CheckAdvertise(f.LoginServer); err != nil {
		return "", fmt.Errorf("the network this machine holds is reached at %s, which stops working with Tailscale: %w", f.LoginServer, err)
	}
	elsewhere := fmt.Errorf("this machine is on the network held at %s, so it cannot hold a new one — choose that machine instead", f.LoginServer)
	if _, ok := control.DialAdmin(serverSocket()); !ok {
		// A server that is set up here but stopped is started again. One
		// that was never here is not: this node's network is somebody
		// else's, and a second one under it would strand it from the first.
		if _, err := os.Stat(serverStatePath); err != nil {
			return "", elsewhere
		}
		if err := controlDaemon().Start(ctx, startWait); err != nil {
			return "", err
		}
	}
	if !holdsOwn(f) {
		return "", elsewhere
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

// --- join ---------------------------------------------------------------

// migrateJoin puts this machine on the network while leaving Tailscale alone:
// it is the machine running the migration, and Tailscale is how it is still
// reaching the others.
func migrateJoin(args []string) error {
	fs := flag.NewFlagSet("migrate join", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	name := fs.String("name", "", "this machine's name on the network")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw := fs.Args()
	if *name != "" && !migrate.ValidName(*name) {
		return fmt.Errorf("%q is not a name makima can use", *name)
	}
	inv, err := checkInvite(strings.Join(raw, " "))
	if err != nil {
		return err
	}
	if err := mustBeRoot(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if f, err := conf.Load(*path); err == nil {
		if f.LoginServer != strings.TrimRight(inv.Server, "/") {
			return fmt.Errorf("this machine is already on the network held at %s — 'makima down' and remove %s to move it", f.LoginServer, *path)
		}
		return bringUp(ctx, *path)
	}
	return joinWith(ctx, *path, inv, *name)
}

// --- cutover ------------------------------------------------------------

type cutoverOpts struct {
	path       string
	name       string
	controller string
	serverSelf bool
	remove     bool
	sshUser    string
	input      migrate.Input

	// ctrlOnTailscale is a controller that switches last — the machine the
	// migration runs on — and is Linux, where Tailscale's firewall drops
	// tunnel traffic until it does. Until then the only honest proof this
	// machine can get is a disco ping, which travels outside the tunnel.
	ctrlOnTailscale bool

	// statePath is where progress is written; migrate.StatePath but in tests.
	statePath string
}

// migrateCutover moves this machine off Tailscale and onto makima, or puts it
// back exactly as it was.
func migrateCutover(args []string) error {
	fs := flag.NewFlagSet("migrate cutover", flag.ExitOnError)
	o := cutoverOpts{statePath: migrate.StatePath}
	fs.StringVar(&o.path, "config", conf.DefaultPath, "config path")
	fs.StringVar(&o.name, "name", "", "this machine's name on the network")
	fs.StringVar(&o.controller, "controller", "", "the machine holding the network, to check the tunnel against")
	fs.BoolVar(&o.serverSelf, "server-self", false, "this machine holds the network")
	fs.BoolVar(&o.remove, "remove", true, "uninstall Tailscale once makima works (otherwise it is left installed, off)")
	fs.StringVar(&o.sshUser, "ssh-user", "", "turn on makima's SSH server for this account, with the keys given on stdin")
	fs.BoolVar(&o.ctrlOnTailscale, "controller-on-tailscale", false, "the controller has not left Tailscale yet; check the path to it, not the tunnel")
	detach := fs.Bool("detach", false, "run in the background, surviving the SSH session that started it")
	fromStdin := fs.Bool("stdin", false, "read the invite and SSH keys as JSON on stdin")
	inputFile := fs.String("input", "", "read them from this file, and delete it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !migrate.ValidName(o.name) || (o.controller != "" && !migrate.ValidName(o.controller)) {
		return errors.New("cutover needs -name, and names makima can use")
	}
	if !o.serverSelf && o.controller == "" {
		return errors.New("cutover needs -controller, or -server-self on the machine holding the network")
	}
	if os.Geteuid() != 0 {
		return migrate.ErrNotRoot
	}

	switch {
	case *fromStdin:
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if len(strings.TrimSpace(string(b))) > 0 {
			if err := json.Unmarshal(b, &o.input); err != nil {
				return fmt.Errorf("read the input: %w", err)
			}
		}
	case *inputFile != "":
		b, err := os.ReadFile(*inputFile)
		os.Remove(*inputFile)
		if err != nil {
			return fmt.Errorf("read the input: %w", err)
		}
		if err := json.Unmarshal(b, &o.input); err != nil {
			return fmt.Errorf("read the input: %w", err)
		}
	}

	if *detach {
		return detachCutover(o, args)
	}

	st := runCutover(context.Background(), o)
	b, _ := json.Marshal(st)
	fmt.Println(string(b))
	return nil
}

// detachCutover starts the cutover again in the background and returns.
//
// It has to outlive the SSH session that asked for it: that session rides on
// Tailscale, which the cutover is about to stop — and under Tailscale SSH the
// session's processes belong to tailscaled, which takes them all down as it
// goes. systemd-run gives it a unit of its own; elsewhere a new session does.
func detachCutover(o cutoverOpts, args []string) error {
	if err := os.MkdirAll(filepath.Dir(migrate.InputPath), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(o.input)
	if err := os.WriteFile(migrate.InputPath, b, 0o600); err != nil {
		return err
	}
	_ = migrate.WriteState(migrate.StatePath, migrate.State{State: migrate.StateStarting, Name: o.name, Detail: "starting"})

	self, err := os.Executable()
	if err != nil {
		return err
	}
	var rest []string
	for _, a := range args {
		if a == "-detach" || a == "--detach" || a == "-stdin" || a == "--stdin" {
			continue
		}
		rest = append(rest, a)
	}
	cmdArgs := append([]string{"migrate", "cutover"}, rest...)
	cmdArgs = append(cmdArgs, "-input", migrate.InputPath)

	if run, err := exec.LookPath("systemd-run"); err == nil && dirExists("/run/systemd/system") {
		unit := "makima-migrate-" + strconv.FormatInt(time.Now().Unix(), 10)
		full := append([]string{
			"--unit", unit, "--collect", "--quiet",
			"--property=StandardOutput=append:" + migrate.LogPath,
			"--property=StandardError=append:" + migrate.LogPath,
			self,
		}, cmdArgs...)
		if out, err := exec.Command(run, full...).CombinedOutput(); err == nil {
			fmt.Println("started", unit)
			return nil
		} else {
			fmt.Fprintf(os.Stderr, "note: systemd-run refused (%s); starting it directly\n", strings.TrimSpace(string(out)))
		}
	}
	return spawnDetached(self, cmdArgs, migrate.LogPath)
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// runCutover is the switch itself. It always ends in a final state, and every
// path out of it that is not "done" leaves Tailscale as it found it.
func runCutover(ctx context.Context, o cutoverOpts) migrate.State {
	os.Setenv("PATH", os.Getenv("PATH")+":/usr/local/bin:/usr/sbin:/sbin:/opt/homebrew/bin")
	st := migrate.State{State: migrate.StateRunning, Name: o.name, PID: os.Getpid()}
	save := func(step, detail string) {
		st.Step, st.Detail = step, detail
		_ = migrate.WriteState(o.statePath, st)
		fmt.Fprintf(os.Stderr, "%s  %s: %s\n", time.Now().Format(time.TimeOnly), step, detail)
	}
	finish := func(state, detail string) migrate.State {
		st.State = state
		save(st.Step, detail)
		return st
	}

	// 1. Refuse before touching anything, if this could not work.
	f, err := conf.Load(o.path)
	member := err == nil
	var inv struct{ server string }
	if o.input.Invite != "" {
		i, err := checkInvite(o.input.Invite)
		if err != nil {
			return finish(migrate.StateFailed, err.Error())
		}
		inv.server = strings.TrimRight(i.Server, "/")
	}
	switch {
	case o.serverSelf && !member:
		return finish(migrate.StateFailed, "this machine was to hold the network, but is not on it")
	case o.serverSelf:
		if _, ok := control.DialAdmin(serverSocket()); !ok {
			return finish(migrate.StateFailed, "the network's server is not running here")
		}
	case member && !f.Managed():
		return finish(migrate.StateFailed, "this machine is on a makima network with no server, and cannot join another")
	case member && inv.server != "" && inv.server != f.LoginServer:
		return finish(migrate.StateFailed, "this machine is already on the network held at "+f.LoginServer)
	case !member && o.input.Invite == "":
		return finish(migrate.StateFailed, "no invite to join with")
	}

	// 2. Tailscale off. It is only stopped here — nothing is forgotten — so
	// starting it again is a complete undo.
	host := migrate.ThisHost()
	ts, found := migrate.FindTailscale(ctx, host)
	if found {
		save("tailscale", "stopping Tailscale")
		if err := ts.Stop(ctx); err != nil {
			_ = ts.Start(ctx)
			return finish(migrate.StateFailed, err.Error())
		}
	}
	rollback := func(reason string) migrate.State {
		save("rollback", "putting Tailscale back: "+reason)
		if !o.serverSelf {
			// The node goes down and stays registered, so another try picks
			// up the same identity. The server, on the machine that holds
			// it, stays: other machines may already be on it.
			d := daemonFor(o.path)
			_ = d.Stop(ctx, stopWait)
		}
		if found {
			if err := ts.Start(ctx); err != nil {
				st.Notes = append(st.Notes, err.Error())
			}
		}
		return finish(migrate.StateRolledBack, reason)
	}

	// 3. On the network.
	save("join", "joining the network")
	jctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	if !member {
		i, _ := checkInvite(o.input.Invite)
		if err := registerNode(jctx, o.path, i, o.name); err != nil {
			cancel()
			return rollback(err.Error())
		}
	}
	err = bringUp(jctx, o.path)
	cancel()
	if err != nil {
		return rollback(err.Error())
	}

	// 4. Proof, not hope.
	save("verify", "checking the tunnel")
	path, err := verifyTunnel(ctx, o, 90*time.Second)
	if err != nil {
		return rollback(err.Error())
	}
	st.Path = path
	if c, err := localapi.Dial(localapi.SocketPath(o.path)); err == nil {
		if s, err := c.Status(); err == nil {
			st.Address = s.Node.Address.String()
		}
	}

	// 5. SSH, for a machine that only had Tailscale's.
	if o.sshUser != "" && o.input.SSHKeys != "" {
		if err := enableOwnSSH(o); err != nil {
			st.Notes = append(st.Notes, "makima's SSH server did not start: "+err.Error())
		}
	}

	// 6. Tailscale away — or left installed and off, if that was the choice.
	if found {
		if o.remove {
			save("remove", "removing Tailscale")
			notes, _ := ts.Remove(ctx)
			st.Notes = append(st.Notes, notes...)
			st.Removed = true
			// Signing out briefly restarts tailscaled, which briefly puts its
			// rules back. Make sure makima came through it.
			if _, err := verifyTunnel(ctx, o, 30*time.Second); err != nil {
				d := daemonFor(o.path)
				_ = d.Stop(ctx, stopWait)
				_ = d.Start(ctx, startWait)
				if _, err := verifyTunnel(ctx, o, 60*time.Second); err != nil {
					st.Notes = append(st.Notes, "the tunnel did not come back after Tailscale was removed — try 'makima down' and 'makima up'")
				}
			}
		} else {
			ts.Disable(ctx)
			st.Notes = append(st.Notes, "Tailscale is still installed, switched off")
		}
	}
	save("done", "on makima")
	return finish(migrate.StateDone, "on makima")
}

// verifyTunnel waits for this machine to be properly on the network: for the
// machine holding it, its server answering at the address the others use; for
// the rest, a packet that goes through the tunnel to that machine and back.
func verifyTunnel(ctx context.Context, o cutoverOpts, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	last := errors.New("makima did not start")
	for time.Now().Before(deadline) {
		if p, err := tunnelOnce(ctx, o); err == nil {
			return p, nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return "", last
}

func tunnelOnce(ctx context.Context, o cutoverOpts) (string, error) {
	c, err := localapi.Dial(localapi.SocketPath(o.path))
	if err != nil {
		return "", errors.New("makima is not running")
	}
	st, err := c.Status()
	if err != nil {
		return "", err
	}
	if !st.Managed {
		return "", errors.New("makima is up but not on a network")
	}
	if o.serverSelf {
		fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if _, err := control.FetchServerKey(fctx, st.Server); err != nil {
			return "", fmt.Errorf("the network's server does not answer at %s", st.Server)
		}
		return "holding the network", nil
	}
	for _, p := range st.Peers {
		if p.Name != o.controller {
			continue
		}
		if !p.Online {
			return "", fmt.Errorf("%s is not online on makima", o.controller)
		}
		if o.ctrlOnTailscale {
			pg, err := c.Ping(o.controller)
			if err != nil || (pg.Latency == 0 && pg.RelayLatency == 0) {
				return "", fmt.Errorf("no path to %s yet", o.controller)
			}
			if pg.Direct {
				return "direct", nil
			}
			return "via relay", nil
		}
		// The server listens on every address, the tunnel's included. A
		// connection accepted — or refused — came back through the tunnel;
		// silence is what Tailscale's firewall rule, or any other, sounds like.
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.Address.String(), "8080"))
		if err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
			return "", fmt.Errorf("nothing comes back from %s through the tunnel", o.controller)
		}
		if conn != nil {
			conn.Close()
		}
		if p.Direct {
			return "direct", nil
		}
		return "via relay", nil
	}
	return "", fmt.Errorf("%s is not on the network yet", o.controller)
}

// enableOwnSSH switches on makima's SSH server with the keys the migration
// brought, so a machine that was only reachable by Tailscale SSH is still
// reachable by ssh.
func enableOwnSSH(o cutoverOpts) error {
	keys := filepath.Join(filepath.Dir(o.path), "authorized_keys")
	lines := strings.Split(strings.TrimSpace(o.input.SSHKeys), "\n")
	sort.Strings(lines)
	if err := os.WriteFile(keys, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	c, err := localapi.Dial(localapi.SocketPath(o.path))
	if err != nil {
		return err
	}
	return c.SetSSH(true, []string{keys}, o.sshUser)
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
	fmt.Print("Uninstall Tailscale from each machine once it is on makima? [Y/n] ")
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
		fmt.Printf("  %-20s %-11s %s\n", m.Name, m.Outcome, m.Detail)
		for _, n := range m.Notes {
			fmt.Printf("  %-20s %-11s note: %s\n", "", "", n)
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
