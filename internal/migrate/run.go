package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Choice is what the person decided, sent back to the run with the plan the
// scan produced.
type Choice struct {
	Plan       Plan              `json:"plan"`
	Controller string            `json:"controller"`
	Advertise  string            `json:"advertise,omitempty"`
	Selected   []string          `json:"selected"`
	Passwords  map[string]string `json:"passwords,omitempty"`
	Remove     bool              `json:"remove_tailscale"`
}

// Action is a step on this machine that needs root, asked of whoever can
// grant it — the app's password prompt, or sudo in a terminal. The same kinds
// and fields are an enum in the app (desktop/src-tauri/src/privileged.rs).
type Action struct {
	Kind       string `json:"kind"`
	Advertise  string `json:"advertise,omitempty"`
	Name       string `json:"name,omitempty"`
	Invites    int    `json:"invites,omitempty"`
	Invite     string `json:"invite,omitempty"`
	Controller string `json:"controller,omitempty"`
	ServerSelf bool   `json:"server_self"`
	Remove     bool   `json:"remove"`
	Verdict    string `json:"verdict,omitempty"`
}

// Args is the makima command line for an action. privileged.rs spells the
// same thing; each side has a test that pins the spelling.
func (a Action) Args() []string {
	switch a.Kind {
	case "migrate-host":
		return []string{"migrate", "host", "-json", "-advertise", a.Advertise, "-name", a.Name, "-invites", strconv.Itoa(a.Invites)}
	case "migrate-join":
		return []string{"migrate", "join", "-name", a.Name, a.Invite}
	case "migrate-cutover":
		args := []string{"migrate", "cutover", "-detach", "-name", a.Name, "-controller", a.Controller}
		if a.ServerSelf {
			args = append(args, "-server-self")
		}
		return append(args, "-remove="+strconv.FormatBool(a.Remove))
	case "migrate-commit":
		if a.Verdict == VerdictKeep || a.Verdict == VerdictAbort {
			return []string{"migrate", "commit", "-" + a.Verdict}
		}
		return []string{"migrate", "commit"}
	}
	return nil
}

// HostResult is what `makima migrate host -json` prints.
type HostResult struct {
	Server  string   `json:"server"`
	Name    string   `json:"name"`
	Invites []string `json:"invites"`
}

// Outcomes a machine can end with.
const (
	Moved       = "moved"       // on makima, verified
	MovedLikely = "moved?"      // on makima as far as the network can tell; not read back
	RolledBack  = "rolled_back" // tried, did not come up, Tailscale put back
	Stayed      = "stayed"      // never touched
)

// Outcome is how one machine ended.
type Outcome struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Outcome string   `json:"outcome"`
	Detail  string   `json:"detail,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Result is how the whole run ended.
type Result struct {
	OK         bool      `json:"ok"`
	Server     string    `json:"server,omitempty"`
	Controller string    `json:"controller,omitempty"`
	Machines   []Outcome `json:"machines"`
	Error      string    `json:"error,omitempty"`
}

// MeshPeer is a machine as this one's makima sees it.
type MeshPeer struct {
	Address string
	Online  bool
}

// Runner carries out a Choice.
type Runner struct {
	SSH     Shell
	Emit    func(Event)
	Version string

	// Elevate runs a root step on this machine and returns what it printed.
	Elevate func(ctx context.Context, a Action) (string, error)

	// Probe checks, from this machine, that the network's server answers
	// without Tailscale's help.
	Probe func(ctx context.Context, server string) error

	// Peers is this machine's makima's view of the network, by name. Empty
	// while this machine is not on it.
	Peers func() map[string]MeshPeer

	// Pubkeys are this person's SSH public keys, given to machines that were
	// reached through Tailscale SSH so makima's own SSH server lets them in.
	Pubkeys func() string

	// LocalState reads this machine's switch report. The state file unless
	// a test says otherwise.
	LocalState func() (State, error)

	// Kit finds binaries for another machine. KitFor unless a test says
	// otherwise.
	Kit func(ctx context.Context, goos, goarch, version string) ([]byte, string, error)

	// Poll is how often a switching machine is checked on, and Wait how long
	// it is given to finish.
	Poll time.Duration
	Wait time.Duration

	mu        sync.Mutex
	outcomes  map[string]*Outcome
	dropped   map[string]bool // machines out of the run, left as they were
	ctrlName  string
	ctrlLate  bool // the controller is this Linux machine, still behind Tailscale's firewall
	localDown bool // this machine's Tailscale is off, so only makima reaches the rest
}

// Makima is where the migration puts makima on other machines.
const Makima = "/usr/local/bin/makima"

// ErrAborted is a run that stopped before changing any machine's network.
var ErrAborted = errors.New("stopped before anything was switched")

type job struct {
	*Candidate
	password string
	invite   string
	server   string
	mesh     bool // uses makima's own SSH server once it is across
}

// Run moves every chosen machine, the controller first and this machine last.
//
// The order is the safety. Nothing leaves Tailscale until makima is on every
// machine and each has shown it can reach the network's server by some route
// that is not Tailscale. The controller switches first, so the rest have
// somewhere to land. This machine switches last, because the whole time before
// that it is steering the others through Tailscale.
func (r *Runner) Run(ctx context.Context, ch Choice) Result {
	if r.Kit == nil {
		r.Kit = KitFor
	}
	if r.Poll == 0 {
		r.Poll = 4 * time.Second
	}
	if r.Wait == 0 {
		r.Wait = 6 * time.Minute
	}
	r.outcomes = map[string]*Outcome{}
	r.dropped = map[string]bool{}

	res := Result{Controller: ch.Controller}
	jobs, ctrl, err := r.prepare(ch)
	if err != nil {
		res.Error = err.Error()
		return r.finish(res, ch)
	}
	r.ctrlName = ctrl.Name
	r.ctrlLate = ctrl.Local && ctrl.Facts != nil && ctrl.Facts.OS == "linux" && ctrl.Facts.Tailscale != ""
	var local *job
	var others []*job
	for _, j := range jobs {
		if j.Local && j != ctrl {
			local = j
		} else if j != ctrl {
			others = append(others, j)
		}
	}

	// 1. makima on every machine, over Tailscale. Harmless: nothing starts.
	r.parallel(jobs, func(j *job) {
		if j.Local {
			return
		}
		if err := r.install(ctx, j); err != nil {
			r.fail(j, "install", Stayed, "could not put makima on it: "+err.Error())
		}
	})
	if r.gone(ctrl) {
		res.Error = fmt.Sprintf("%s could not be set up to hold the network, so nothing was switched", ctrl.Name)
		return r.finish(res, ch)
	}

	// 2. The network, on the machine chosen to hold it.
	advertise := strings.TrimSpace(ch.Advertise)
	if advertise == "" {
		advertise = ctrl.Reach
	}
	if err := CheckAdvertise(advertise); err != nil {
		r.fail(ctrl, "network", Stayed, err.Error())
		res.Error = err.Error()
		return r.finish(res, ch)
	}
	var pending []*job
	for _, j := range append(others, local) {
		if j != nil && !r.gone(j) {
			pending = append(pending, j)
		}
	}
	r.step(ctrl, "network", "running", "starting the network at "+advertise)
	host, err := r.host(ctx, ctrl, advertise, len(pending))
	if err != nil {
		r.fail(ctrl, "network", Stayed, err.Error())
		res.Error = fmt.Sprintf("the network could not be started on %s: %v", ctrl.Name, err)
		return r.finish(res, ch)
	}
	res.Server = host.Server
	r.step(ctrl, "network", "ok", "holding the network at "+host.Server)
	for i, j := range pending {
		j.server = host.Server
		if i < len(host.Invites) {
			j.invite = host.Invites[i]
		}
	}
	ctrl.server = host.Server

	// 3. Every other machine proves it can reach the server without
	// Tailscale. One that cannot would lose everything the moment Tailscale
	// stopped, so it is left alone.
	r.parallel(pending, func(j *job) {
		r.step(j, "reach", "running", "checking it can reach "+ctrl.Name+" without Tailscale")
		if j.invite == "" {
			r.fail(j, "reach", Stayed, "no invite was made for it")
			return
		}
		if err := r.reach(ctx, j); err != nil {
			r.fail(j, "reach", Stayed, fmt.Sprintf("cannot reach %s without Tailscale (%v) — it stays on Tailscale", ctrl.Name, err))
			return
		}
		r.step(j, "reach", "ok", "")
	})

	// 4. This machine joins now, alongside Tailscale. It has to: every
	// removal of Tailscale below is confirmed by this machine reaching the
	// device over makima, so it must be on makima before anything is.
	self := ctrl
	if !ctrl.Local {
		self = local
	}
	if local != nil && !r.gone(local) {
		r.step(local, "join", "running", "joining the network")
		if _, err := r.Elevate(ctx, Action{Kind: "migrate-join", Name: local.Name, Invite: local.invite}); err != nil {
			r.fail(local, "join", Stayed, "could not join: "+err.Error())
		} else {
			r.step(local, "join", "ok", "")
		}
	}

	// The gate. Past this point devices start leaving Tailscale, so it is
	// passed only when this machine is on the network — having reached the
	// device holding it without Tailscale — and somebody else is coming too.
	var remotes []*job
	for _, j := range jobs {
		if !j.Local && !r.gone(j) {
			remotes = append(remotes, j)
		}
	}
	switch {
	case self == nil:
		res.Error = "this device has to come along — it is the one that confirms each of the others over makima. Nothing was switched"
		return r.finish(res, ch)
	case r.gone(self) && !ctrl.Local:
		res.Error = fmt.Sprintf("this device could not get onto the network at %s without Tailscale, so moving anything would have left it cut off. Nothing was switched", host.Server)
		return r.finish(res, ch)
	case !ctrl.Local && r.gone(ctrl):
		res.Error = fmt.Sprintf("%s could not be set up, so nothing was switched", ctrl.Name)
		return r.finish(res, ch)
	case len(remotes) == 0:
		res.Error = "no other device can reach the network without Tailscale, so there is nothing to move. Nothing was switched"
		return r.finish(res, ch)
	}

	// 5. Every device starts its switch — the remote ones first, while
	// Tailscale still reaches them, then this one. Each stops Tailscale,
	// joins, checks the tunnel, and then holds: Tailscale stopped but still
	// installed, waiting to be confirmed.
	r.parallel(remotes, func(j *job) { r.startRemote(ctx, j, ch.Remove, j == ctrl) })
	var started []*job
	for _, j := range remotes {
		if !r.gone(j) {
			started = append(started, j)
		}
	}
	if !ctrl.Local && r.gone(ctrl) {
		r.abortAll(ctx, started)
		res.Error = fmt.Sprintf("%s's switch did not start, so the rest were called off", ctrl.Name)
		return r.finish(res, ch)
	}
	if !r.startLocal(ctx, self, ctrl, ch.Remove) {
		r.abortAll(ctx, started)
		res.Error = "this device's switch did not start, so the rest were called off and go back to Tailscale"
		return r.finish(res, ch)
	}
	r.localDown = true

	// 6. Wait for each to be holding, reading its report over makima.
	holding := map[string]bool{}
	var mu sync.Mutex
	r.parallel(append(append([]*job{}, started...), self), func(j *job) {
		if r.awaitHolding(ctx, j) {
			mu.Lock()
			holding[j.ID] = true
			mu.Unlock()
		}
	})

	// 7. Confirm, over makima and nothing else. The controller first: if it
	// cannot be confirmed nothing else should be.
	order := append([]*job{}, started...)
	for i, j := range order {
		if j == ctrl {
			order[0], order[i] = order[i], order[0]
		}
	}
	committed := 0
	if !ctrl.Local && !holding[ctrl.ID] {
		r.abortAll(ctx, append(started, self))
		res.Error = fmt.Sprintf("%s never came up on makima, so everything was called off and goes back to Tailscale", ctrl.Name)
		return r.finish(res, ch)
	}
	if !ctrl.Local {
		if r.commit(ctx, ctrl, VerdictCommit) {
			committed++
		} else {
			r.abortAll(ctx, append(started, self))
			res.Error = fmt.Sprintf("%s could not be confirmed over makima, so everything was called off and goes back to Tailscale", ctrl.Name)
			return r.finish(res, ch)
		}
		order = order[1:]
	}
	var cmu sync.Mutex
	r.parallel(order, func(j *job) {
		if holding[j.ID] && r.commit(ctx, j, VerdictCommit) {
			cmu.Lock()
			committed++
			cmu.Unlock()
		}
	})

	// 8. This machine last. It gives up Tailscale only if everybody it
	// could still need Tailscale for has left it too. On a Mac, where the
	// two can run side by side, a partial move keeps both; elsewhere
	// Tailscale's firewall would break makima, so it is one or the other.
	failed := len(started) - committed
	verdict := VerdictCommit
	switch {
	case !holding[self.ID]:
		verdict = VerdictAbort
	case failed > 0 && self.Facts != nil && self.Facts.OS == "darwin":
		verdict = VerdictKeep
	case failed > 0 && committed == 0:
		verdict = VerdictAbort
	}
	r.commit(ctx, self, verdict)
	return r.finish(res, ch)
}

// prepare checks the choice against the plan and makes a job for each machine.
func (r *Runner) prepare(ch Choice) ([]*job, *job, error) {
	chosen := map[string]bool{}
	for _, id := range ch.Selected {
		chosen[id] = true
	}
	chosen[ch.Controller] = true
	// This device always comes: it is what confirms each of the others.
	for _, c := range ch.Plan.Machines {
		if c.Local {
			chosen[c.ID] = true
		}
	}

	var jobs []*job
	var ctrl *job
	for i := range ch.Plan.Machines {
		c := &ch.Plan.Machines[i]
		if !chosen[c.ID] || !c.Eligible {
			continue
		}
		if !ValidName(c.Name) {
			return nil, nil, fmt.Errorf("%q is not a name makima can use", c.Name)
		}
		j := &job{Candidate: c, password: ch.Passwords[c.ID]}
		if c.NeedsPassword && j.password == "" {
			r.fail(j, "install", Stayed, "its sudo needs a password, and none was given")
			continue
		}
		// Reached through Tailscale SSH, with nothing else listening: once
		// Tailscale is gone makima's own SSH server takes over, with this
		// person's keys, so `ssh` to it keeps working.
		j.mesh = c.Facts != nil && c.Facts.Via == "tailscale" && !c.Facts.OpenSSH
		r.outcomes[c.ID] = &Outcome{ID: c.ID, Name: c.Name, Outcome: Stayed}
		jobs = append(jobs, j)
		if c.ID == ch.Controller {
			ctrl = j
		}
	}
	if ctrl == nil {
		return nil, nil, errors.New("the machine chosen to hold the network cannot be moved")
	}
	if r.gone(ctrl) {
		return nil, nil, fmt.Errorf("%s needs its sudo password to hold the network", ctrl.Name)
	}
	// The controller goes first in every list.
	for i, j := range jobs {
		if j == ctrl {
			jobs[0], jobs[i] = jobs[i], jobs[0]
		}
	}
	return jobs, ctrl, nil
}

// CheckAdvertise refuses an address that only works while Tailscale does.
func CheckAdvertise(advertise string) error {
	if advertise == "" {
		return errors.New("there is no address other machines could reach it at — give one")
	}
	host := advertise
	if u, err := url.Parse(advertise); err == nil && u.Host != "" {
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(advertise); err == nil {
		host = h
	}
	if IsTailscaleHost(host) {
		return fmt.Errorf("%s is a Tailscale address, and Tailscale is what is being turned off — use the machine's LAN or public address", host)
	}
	if a, err := netip.ParseAddr(host); err == nil && (a.IsLoopback() || a.IsUnspecified()) {
		return fmt.Errorf("%s is not an address other machines can reach", host)
	}
	return nil
}

func (r *Runner) target(j *job) Target {
	t := Target{Addr: j.IPv4()}
	if j.Access != nil {
		t.User = j.Access.User
	}
	return t
}

// asRoot wraps a script so it runs as root on j, feeding sudo its password
// ahead of whatever else the script reads.
//
// -k makes sudo ask even if it remembers a recent password, so the password
// line is always the one it consumes and never falls through to the script.
func asRoot(j *job, script string, stdin []byte) (string, []byte) {
	sudo := ""
	if j.Facts != nil {
		sudo = j.Facts.Sudo
	}
	switch sudo {
	case "root":
		return script, stdin
	case "password":
		return "sudo -k -S -p '' sh -c " + ShellQuote(script), append([]byte(j.password+"\n"), stdin...)
	default:
		return "sudo -n sh -c " + ShellQuote(script), stdin
	}
}

func (r *Runner) remote(ctx context.Context, j *job, script string, stdin []byte, root bool, short time.Duration) (string, error) {
	if root {
		script, stdin = asRoot(j, script, stdin)
	}
	return runWaiting(ctx, r.SSH, r.target(j), script, stdin, short, func(u string) {
		r.emit(Event{Type: "auth", Machine: j.ID, URL: u})
	})
}

// install puts the four binaries on a machine, unless the same version is
// there already.
func (r *Runner) install(ctx context.Context, j *job) error {
	if j.Facts.Makima == r.Version && r.Version != "" && r.Version != "dev" {
		r.step(j, "install", "ok", "makima "+r.Version+" is already there")
		return nil
	}
	r.step(j, "install", "running", "putting makima on it")
	kit, from, err := r.Kit(ctx, j.Facts.OS, j.Facts.Arch, r.Version)
	if err != nil {
		return err
	}
	r.step(j, "install", "running", "copying makima for "+j.Facts.OS+"/"+j.Facts.Arch+" from "+from)
	out, err := r.remote(ctx, j, UploadScript, kit, false, 3*time.Minute)
	if err != nil {
		return fmt.Errorf("copy it there: %w", err)
	}
	path := lastLine(out)
	if !strings.HasPrefix(path, "/tmp/makima-kit.") || strings.ContainsAny(path, " '\"\\;$`") {
		return fmt.Errorf("copy it there: unexpected answer %q", path)
	}
	out, err = r.remote(ctx, j, "set -- "+ShellQuote(path)+"\n"+InstallScript, nil, true, 2*time.Minute)
	if err != nil {
		return err
	}
	r.step(j, "install", "ok", "makima "+lastLine(out))
	return nil
}

// host starts the network on the controller and mints an invite per machine.
func (r *Runner) host(ctx context.Context, ctrl *job, advertise string, invites int) (HostResult, error) {
	a := Action{Kind: "migrate-host", Advertise: advertise, Name: ctrl.Name, Invites: invites}
	var out string
	var err error
	if ctrl.Local {
		out, err = r.Elevate(ctx, a)
	} else {
		out, err = r.remote(ctx, ctrl, commandLine(Makima, a.Args()), nil, true, 2*time.Minute)
	}
	if err != nil {
		return HostResult{}, err
	}
	var h HostResult
	if err := json.Unmarshal([]byte(lastJSON(out)), &h); err != nil {
		return HostResult{}, fmt.Errorf("unexpected answer: %s", lastLine(out))
	}
	if h.Server == "" || len(h.Invites) < invites {
		return HostResult{}, errors.New("it started, but did not hand back an invite for every machine")
	}
	return h, nil
}

// reach asks a machine whether it can get to the server without Tailscale.
func (r *Runner) reach(ctx context.Context, j *job) error {
	if j.Local {
		return r.Probe(ctx, j.server)
	}
	_, err := r.remote(ctx, j, commandLine(Makima, []string{"migrate", "probe", j.server}), nil, false, 30*time.Second)
	return err
}

// startRemote starts a machine's switch, over Tailscale.
//
// The switch runs on the machine by itself, detached from this SSH session —
// which dies the moment Tailscale stops, and with Tailscale SSH takes every
// process it started down with it.
func (r *Runner) startRemote(ctx context.Context, j *job, remove, serverSelf bool) {
	r.step(j, "switch", "running", "leaving Tailscale")
	args := []string{"migrate", "cutover", "-detach", "-stdin", "-name", j.Name, "-remove=" + strconv.FormatBool(remove)}
	if serverSelf {
		args = append(args, "-server-self")
	} else {
		args = append(args, "-controller", r.ctrlName)
		if r.ctrlLate {
			args = append(args, "-controller-on-tailscale")
		}
	}
	in := Input{Invite: j.invite}
	if j.mesh {
		if keys := r.pubkeys(); keys != "" {
			in.SSHKeys = keys
			args = append(args, "-ssh-user", j.Facts.User)
		}
	}
	stdin, _ := json.Marshal(in)
	if _, err := r.remote(ctx, j, commandLine(Makima, args), append(stdin, '\n'), true, time.Minute); err != nil {
		r.fail(j, "switch", Stayed, "could not start the switch: "+err.Error())
	}
}

// startLocal starts this machine's own switch, detached like the others.
func (r *Runner) startLocal(ctx context.Context, self, ctrl *job, remove bool) bool {
	r.step(self, "switch", "running", "leaving Tailscale")
	a := Action{Kind: "migrate-cutover", Name: self.Name, Controller: ctrl.Name, ServerSelf: self == ctrl, Remove: remove}
	if _, err := r.Elevate(ctx, a); err != nil {
		r.fail(self, "switch", Stayed, "could not start: "+err.Error())
		return false
	}
	return true
}

// awaitHolding waits for a machine to report it is on makima and holding.
func (r *Runner) awaitHolding(ctx context.Context, j *job) bool {
	deadline := time.Now().Add(r.Wait)
	last := ""
	for time.Now().Before(deadline) {
		st, err := r.stateOf(ctx, j)
		if err == nil {
			if st.State == StateWaiting {
				r.step(j, "switch", "ok", "on makima, "+firstNonEmpty(st.Path, "tunnel checked")+" — confirming")
				return true
			}
			if st.Final() {
				r.settle(j, st)
				return false
			}
			if st.Detail != last && st.Detail != "" {
				last = st.Detail
				r.step(j, "switch", "running", st.Detail)
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(r.Poll):
		}
	}
	r.set(j, Stayed, "could not be reached over makima; it puts Tailscale back by itself")
	r.step(j, "switch", "failed", "could not be reached over makima — it goes back to Tailscale by itself")
	return false
}

// commit gives a holding machine its verdict — for another machine, over
// makima and only over makima: reaching it that way is the proof that it
// may give up Tailscale.
func (r *Runner) commit(ctx context.Context, j *job, verdict string) bool {
	if verdict == VerdictCommit {
		r.step(j, "confirm", "running", "confirmed over makima — removing Tailscale")
	}
	var out string
	var err error
	if j.Local {
		out, err = r.Elevate(ctx, Action{Kind: "migrate-commit", Verdict: verdict})
	} else {
		args := []string{"migrate", "commit"}
		if verdict != VerdictCommit {
			args = append(args, "-"+verdict)
		}
		t, ok := r.meshTarget(j)
		if !ok {
			err = errors.New("it is not on the network as far as this device can see")
		} else {
			script, stdin := asRoot(j, commandLine(Makima, args), nil)
			cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
			out, err = r.SSH.Run(cctx, t, script, stdin, nil)
			cancel()
		}
	}
	if err != nil {
		if verdict == VerdictCommit {
			r.set(j, Stayed, "could not be confirmed over makima ("+err.Error()+"); it puts Tailscale back by itself")
			r.step(j, "confirm", "failed", "could not be confirmed over makima — it goes back to Tailscale by itself")
		}
		return false
	}
	st, perr := ReadState([]byte(lastJSON(out)))
	if perr != nil || !st.Final() {
		r.set(j, Stayed, "confirmed, but it did not say how it finished")
		return false
	}
	r.settle(j, st)
	return st.State == StateDone
}

// abortAll calls off switches that have started, where they can be reached.
// Any that cannot be reached call themselves off when nobody confirms them.
func (r *Runner) abortAll(ctx context.Context, jobs []*job) {
	r.parallel(jobs, func(j *job) {
		if j == nil || r.outcome(j).Outcome == RolledBack {
			return // finished already, and back on Tailscale
		}
		if !r.commit(ctx, j, VerdictAbort) && r.outcome(j).Outcome != RolledBack {
			r.set(j, Stayed, "called off; it goes back to Tailscale by itself")
		}
	})
}

// stateOf reads a machine's switch report: this machine's from disk, the
// others' over SSH.
func (r *Runner) stateOf(ctx context.Context, j *job) (State, error) {
	if j.Local {
		if r.LocalState != nil {
			return r.LocalState()
		}
		b, err := os.ReadFile(StatePath)
		if err != nil {
			return State{}, err
		}
		return ReadState(b)
	}
	return r.readState(ctx, j)
}

// meshTarget is where a machine is reached over makima.
func (r *Runner) meshTarget(j *job) (Target, bool) {
	p, ok := r.peers()[j.Name]
	if !ok || p.Address == "" {
		return Target{}, false
	}
	t := Target{Addr: p.Address, User: r.target(j).User}
	if j.mesh {
		t.Port = 2222
		if j.Facts != nil {
			t.User = j.Facts.User
		}
	} else {
		_ = r.SSH.Pin(p.Address, j.HostKeys)
	}
	return t, true
}

// readState reads a machine's switch report, through Tailscale while that
// still works and over makima once it is on it — whichever answers first.
func (r *Runner) readState(ctx context.Context, j *job) (State, error) {
	type answer struct {
		st  State
		err error
	}
	var targets []Target
	if !r.localDown {
		targets = append(targets, r.target(j))
	}
	if t, ok := r.meshTarget(j); ok {
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return State{}, errors.New("no way to reach it")
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ch := make(chan answer, len(targets))
	for _, t := range targets {
		go func(t Target) {
			out, err := r.SSH.Run(cctx, t, "cat "+StatePath, nil, nil)
			if err != nil {
				ch <- answer{err: err}
				return
			}
			st, err := ReadState([]byte(out))
			ch <- answer{st, err}
		}(t)
	}
	var last error
	for range targets {
		a := <-ch
		if a.err == nil {
			return a.st, nil
		}
		last = a.err
	}
	return State{}, last
}

// settle records a machine's final report.
func (r *Runner) settle(j *job, st State) {
	r.mu.Lock()
	o := r.outcomes[j.ID]
	o.Notes = st.Notes
	r.mu.Unlock()
	switch st.State {
	case StateDone:
		detail := "on makima"
		if st.Path != "" {
			detail += ", " + st.Path
		}
		if st.Removed {
			detail += "; Tailscale removed"
		}
		r.set(j, Moved, detail)
		r.step(j, "switch", "ok", detail)
	case StateRolledBack:
		r.set(j, RolledBack, st.Detail)
		r.step(j, "switch", "failed", "put back on Tailscale: "+st.Detail)
	default:
		r.set(j, Stayed, st.Detail)
		r.step(j, "switch", "failed", st.Detail)
	}
}

func (r *Runner) finish(res Result, ch Choice) Result {
	res.OK = res.Error == ""
	for _, c := range ch.Plan.Sorted() {
		o, ok := r.outcomes[c.ID]
		if !ok {
			why := c.Why
			if why == "" {
				why = "not chosen"
			}
			res.Machines = append(res.Machines, Outcome{ID: c.ID, Name: c.Name, Outcome: Stayed, Detail: why})
			continue
		}
		if o.Outcome != Moved && o.Outcome != MovedLikely {
			res.OK = false
		}
		if o.Outcome == Stayed && o.Detail == "" {
			o.Detail = "not moved — it is exactly as it was, on Tailscale"
		}
		res.Machines = append(res.Machines, *o)
	}
	r.emit(Event{Type: "result", Result: &res})
	return res
}

func (r *Runner) pubkeys() string {
	if r.Pubkeys == nil {
		return ""
	}
	return r.Pubkeys()
}

func (r *Runner) peers() map[string]MeshPeer {
	if r.Peers == nil {
		return nil
	}
	return r.Peers()
}

func (r *Runner) parallel(jobs []*job, f func(*job)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j *job) {
			defer wg.Done()
			defer func() { <-sem }()
			f(j)
		}(j)
	}
	wg.Wait()
}

func (r *Runner) emit(e Event) {
	if r.Emit != nil {
		r.Emit(e)
	}
}

func (r *Runner) step(j *job, step, state, detail string) {
	r.emit(Event{Type: "step", Machine: j.ID, Step: step, State: state, Detail: detail})
}

func (r *Runner) set(j *job, outcome, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.outcomes[j.ID]
	if !ok {
		o = &Outcome{ID: j.ID, Name: j.Name}
		r.outcomes[j.ID] = o
	}
	o.Outcome, o.Detail = outcome, detail
}

func (r *Runner) fail(j *job, step, outcome, detail string) {
	r.set(j, outcome, detail)
	r.mu.Lock()
	r.dropped[j.ID] = true
	r.mu.Unlock()
	r.step(j, step, "failed", detail)
}

func (r *Runner) outcome(j *job) Outcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return *r.outcomes[j.ID]
}

// gone says a machine has dropped out of the run.
func (r *Runner) gone(j *job) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped[j.ID]
}

// commandLine spells a command for a shell.
func commandLine(bin string, args []string) string {
	parts := []string{ShellQuote(bin)}
	for _, a := range args {
		parts = append(parts, ShellQuote(a))
	}
	return strings.Join(parts, " ")
}

// lastJSON is the last line of output that looks like a JSON object: the
// commands print their answer last, after anything they had to say on the way.
func lastJSON(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); strings.HasPrefix(l, "{") {
			return l
		}
	}
	return strings.TrimSpace(out)
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
