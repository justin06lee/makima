package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
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
	Kind      string `json:"kind"`
	Advertise string `json:"advertise,omitempty"`
	Name      string `json:"name,omitempty"`
	Invites   int    `json:"invites,omitempty"`
	Invite    string `json:"invite,omitempty"`
}

// Args is the makima command line for an action. privileged.rs spells the
// same thing; each side has a test that pins the spelling.
func (a Action) Args() []string {
	switch a.Kind {
	case "migrate-host":
		return []string{"migrate", "host", "-json", "-advertise", a.Advertise, "-name", a.Name, "-invites", fmt.Sprint(a.Invites)}
	case "migrate-join":
		return []string{"migrate", "join", "-name", a.Name, a.Invite}
	case "migrate-retire":
		return []string{"migrate", "retire"}
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
	Moved  = "moved"  // on makima, reached over it, Tailscale removed
	Both   = "both"   // on makima, reached over it, Tailscale still running beside it
	Stayed = "stayed" // Tailscale as it was — never joined, or joined but not reached over makima
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
	Direct  bool
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

	// Pubkeys are this person's SSH public keys. Every machine gets them, so
	// that ssh reaches it the ordinary way once Tailscale SSH is gone.
	Pubkeys func() string

	// Kit finds binaries for another machine. KitFor unless a test says
	// otherwise.
	Kit func(ctx context.Context, goos, goarch, version string) ([]byte, string, error)

	// Wait is how long a machine that has joined is given to be reached over
	// makima, and Poll how often it is tried in that time.
	Wait time.Duration
	Poll time.Duration

	mu       sync.Mutex
	outcomes map[string]*Outcome
	dropped  map[string]bool // machines out of the run
}

// Makima is where the migration puts makima on other machines.
const Makima = "/usr/local/bin/makima"

type job struct {
	*Candidate
	password string
	invite   string
	mesh     bool // makima's own SSH server takes the person's keys: nothing else listens for SSH
	path     string
}

// Run puts every chosen machine on makima, then takes Tailscale off the ones
// this machine has reached over makima.
//
// Nothing here stops Tailscale. makima runs beside it, on addresses of its own
// (netcfg.MeshRange), so every step before the last only adds: makima goes on
// each machine, the network starts, each machine joins it — and Tailscale is
// how each is reached the whole time. A machine loses Tailscale only once this
// one has logged in to it over makima, and that removal is itself done over
// makima, so the session doing it does not depend on what it is removing. A
// machine that cannot be reached over makima keeps Tailscale, exactly as
// reachable as it was.
func (r *Runner) Run(ctx context.Context, ch Choice) Result {
	if r.Kit == nil {
		r.Kit = KitFor
	}
	if r.Wait == 0 {
		r.Wait = 2 * time.Minute
	}
	if r.Poll == 0 {
		r.Poll = 3 * time.Second
	}
	r.outcomes = map[string]*Outcome{}
	r.dropped = map[string]bool{}

	res := Result{Controller: ch.Controller}
	keys := r.pubkeys()
	if keys == "" {
		res.Error = "this device has no SSH key to log in to the others with once Tailscale SSH is gone — make one with 'ssh-keygen -t ed25519' and try again. Nothing was changed"
		return r.finish(res, ch)
	}
	jobs, ctrl, err := r.prepare(ch)
	if err != nil {
		res.Error = err.Error()
		return r.finish(res, ch)
	}
	var local *job
	var remotes, others []*job
	for _, j := range jobs {
		switch {
		case j.Local:
			local = j
		default:
			remotes = append(remotes, j)
			if j != ctrl {
				others = append(others, j)
			}
		}
	}
	if local == nil {
		res.Error = "this device has to come along — it is the one that reaches each of the others over makima. Nothing was changed"
		return r.finish(res, ch)
	}

	// 1. makima on every machine, over Tailscale. Nothing starts.
	r.parallel(remotes, func(j *job) {
		if err := r.install(ctx, j); err != nil {
			r.fail(j, "install", Stayed, "could not put makima on it: "+err.Error())
		}
	})
	if r.gone(ctrl) {
		res.Error = fmt.Sprintf("%s could not be set up to hold the network, so nothing was changed", ctrl.Name)
		return r.finish(res, ch)
	}

	// 2. This person's SSH keys on each, so ssh keeps working without
	// Tailscale SSH.
	r.parallel(r.live(remotes), func(j *job) { r.authorize(ctx, j, keys) })

	// 3. The network, on the machine chosen to hold it.
	advertise := strings.TrimSpace(ch.Advertise)
	if advertise == "" {
		advertise = ctrl.Reach
	}
	if err := CheckAdvertise(advertise); err != nil {
		r.fail(ctrl, "network", Stayed, err.Error())
		res.Error = err.Error() + ". Nothing was changed"
		return r.finish(res, ch)
	}
	pending := r.live(others)
	if local != ctrl {
		pending = append(pending, local)
	}
	r.step(ctrl, "network", "running", "starting the network at "+advertise)
	host, err := r.host(ctx, ctrl, advertise, len(pending), keys)
	if err != nil {
		r.fail(ctrl, "network", Stayed, err.Error())
		res.Error = fmt.Sprintf("the network could not be started on %s: %v. Every device still has Tailscale, exactly as before", ctrl.Name, err)
		return r.finish(res, ch)
	}
	res.Server = host.Server
	r.step(ctrl, "network", "ok", "holding the network at "+host.Server)
	for i, j := range pending {
		if i < len(host.Invites) {
			j.invite = host.Invites[i]
		}
	}

	// 4. Each of the rest checks it can reach the server without Tailscale,
	// and joins. Tailscale stays up on all of them.
	r.parallel(pending, func(j *job) { r.join(ctx, j, host.Server, ctrl.Name, keys) })
	if r.gone(local) {
		res.Error = "this device could not join the network, so no device could be reached over makima — and Tailscale was removed from none of them. " + r.outcome(local).Detail
		for _, j := range r.live(remotes) {
			r.set(j, Stayed, "on makima beside Tailscale, but not reached over it from this device — Tailscale is untouched")
		}
		return r.finish(res, ch)
	}

	// 5. Reached over makima, from here: ssh to its makima address.
	r.parallel(r.live(remotes), func(j *job) { r.check(ctx, j) })
	reached := r.live(remotes)

	// 6. Tailscale off the ones that were reached — or left running beside
	// makima everywhere, if that was the choice.
	if !ch.Remove {
		for _, j := range append(reached, local) {
			r.set(j, Both, "on makima"+j.pathNote()+"; Tailscale left running beside it")
		}
		return r.finish(res, ch)
	}
	r.parallel(reached, func(j *job) { r.retireRemote(ctx, j) })

	// This device last, and only once every device that came along was
	// reached: until then it may still need Tailscale to get to one of them.
	var behind []string
	for _, j := range remotes {
		if r.outcome(j).Outcome != Moved {
			behind = append(behind, j.Name)
		}
	}
	if len(behind) > 0 {
		r.set(local, Both, fmt.Sprintf("on makima; Tailscale kept here, because %s %s not on makima yet", list(behind), map[bool]string{true: "is", false: "are"}[len(behind) == 1]))
		r.step(local, "remove", "ok", r.outcome(local).Detail)
		return r.finish(res, ch)
	}
	r.retireLocal(ctx, local)
	return r.finish(res, ch)
}

// prepare checks the choice against the plan and makes a job for each machine.
func (r *Runner) prepare(ch Choice) ([]*job, *job, error) {
	chosen := map[string]bool{}
	for _, id := range ch.Selected {
		chosen[id] = true
	}
	chosen[ch.Controller] = true
	// This device always comes: it is what reaches each of the others.
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
		r.outcomes[c.ID] = &Outcome{ID: c.ID, Name: c.Name, Outcome: Stayed}
		if c.NeedsPassword && j.password == "" {
			r.fail(j, "install", Stayed, "its sudo needs a password, and none was given")
		}
		// Reached through Tailscale SSH, with nothing else listening: makima's
		// own SSH server takes this person's keys, so ssh to it keeps working.
		j.mesh = c.Facts != nil && c.Facts.Via == "tailscale" && !c.Facts.OpenSSH
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
		return fmt.Errorf("%s is a Tailscale address, and Tailscale is what is being replaced — use the machine's LAN or public address", host)
	}
	if a, err := netip.ParseAddr(host); err == nil && (a.IsLoopback() || a.IsUnspecified()) {
		return fmt.Errorf("%s is not an address other machines can reach", host)
	}
	return nil
}

// target is a machine through Tailscale, as the scan logged in to it.
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

// remote runs a script on j through Tailscale.
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
	if r.gone(j) {
		return nil
	}
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

// authorize puts this person's public keys in the authorized_keys of the
// account the scan logged in as, then tries an ordinary ssh login at the
// machine's own address — no Tailscale, no makima — to say whether that works
// too. A machine with nothing listening for ordinary SSH gets makima's own SSH
// server instead, when it joins.
//
// Nothing here is fatal. What matters is ssh over makima, and that is what
// decides, later, whether Tailscale comes off.
func (r *Runner) authorize(ctx context.Context, j *job, keys string) {
	if j.mesh {
		r.step(j, "keys", "ok", "nothing listens for ordinary SSH there, so makima's own SSH server takes your keys")
		return
	}
	who := j.Facts.User
	r.step(j, "keys", "running", "adding your SSH keys for "+who)
	out, err := r.remote(ctx, j, AuthorizeScript, []byte(keys+"\n"), false, 30*time.Second)
	if err != nil || !strings.Contains(out, "added=") {
		if err == nil {
			err = fmt.Errorf("unexpected answer %q", lastLine(out))
		}
		r.step(j, "keys", "failed", "could not add your SSH keys ("+err.Error()+") — ssh over makima may not let you in")
		return
	}
	detail := "your SSH keys are there for " + who
	if j.Reach != "" {
		_ = r.SSH.Pin(j.Reach, j.HostKeys)
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		out, err := r.SSH.Run(cctx, Target{Addr: j.Reach, User: who}, CheckScript, nil, nil)
		cancel()
		if err == nil && strings.Contains(out, "makima-ok") {
			detail = "ordinary SSH works at " + j.Reach + ", without Tailscale"
		} else {
			detail += "; ordinary SSH at " + j.Reach + " did not answer from here, so makima is what it is reached over"
		}
	}
	r.step(j, "keys", "ok", detail)
}

// host starts the network on the controller and mints an invite per machine.
func (r *Runner) host(ctx context.Context, ctrl *job, advertise string, invites int, keys string) (HostResult, error) {
	a := Action{Kind: "migrate-host", Advertise: advertise, Name: ctrl.Name, Invites: invites}
	var out string
	var err error
	if ctrl.Local {
		out, err = r.Elevate(ctx, a)
	} else {
		args := append(a.Args(), "-stdin")
		in := Input{}
		if ctrl.mesh {
			args = append(args, "-ssh-user", ctrl.Facts.User)
			in.SSHKeys = keys
		}
		stdin, _ := json.Marshal(in)
		out, err = r.remote(ctx, ctrl, commandLine(Makima, args), append(stdin, '\n'), true, 3*time.Minute)
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

// join puts a machine on the network, beside Tailscale, once it has shown it
// can reach the server by a route that is not Tailscale's.
func (r *Runner) join(ctx context.Context, j *job, server, ctrlName, keys string) {
	r.step(j, "join", "running", "checking it can reach "+ctrlName+" without Tailscale")
	if j.invite == "" {
		r.fail(j, "join", Stayed, "no invite was made for it")
		return
	}
	var err error
	if j.Local {
		err = r.Probe(ctx, server)
	} else {
		_, err = r.remote(ctx, j, commandLine(Makima, []string{"migrate", "probe", server}), nil, false, 30*time.Second)
	}
	if err != nil {
		r.fail(j, "join", Stayed, fmt.Sprintf("cannot reach %s without Tailscale (%v) — it stays on Tailscale, untouched", ctrlName, err))
		return
	}

	r.step(j, "join", "running", "joining the network, beside Tailscale")
	if j.Local {
		_, err = r.Elevate(ctx, Action{Kind: "migrate-join", Name: j.Name, Invite: j.invite})
	} else {
		// The invite is a credential, so it goes down stdin — never onto a
		// command line where ps would show it.
		args := []string{"migrate", "join", "-stdin", "-name", j.Name}
		in := Input{Invite: j.invite}
		if j.mesh {
			args = append(args, "-ssh-user", j.Facts.User)
			in.SSHKeys = keys
		}
		stdin, _ := json.Marshal(in)
		_, err = r.remote(ctx, j, commandLine(Makima, args), append(stdin, '\n'), true, 3*time.Minute)
	}
	if err != nil {
		r.fail(j, "join", Stayed, "could not join: "+err.Error()+" — Tailscale is untouched")
		return
	}
	r.step(j, "join", "ok", "on the network, beside Tailscale")
}

// check logs in to a machine over makima: ssh to its makima address, and a
// command that answers. Only a machine reached that way may lose Tailscale —
// it is the proof that makima is a way in once Tailscale is gone.
func (r *Runner) check(ctx context.Context, j *job) {
	r.step(j, "verify", "running", "reaching it over makima")
	deadline := time.Now().Add(r.Wait)
	why := "it never showed up on the network"
	for {
		peers := r.peers()
		p, ok := peers[j.Name]
		switch {
		case peers == nil:
			why = "this device's makima is not answering"
		case !ok:
			why = "it never showed up on the network"
		case !p.Online:
			why = "it is on the network, but no connection to it came up — something between the two, most likely a firewall, is dropping UDP 51820"
		default:
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			out, err := r.SSH.Run(cctx, r.meshTarget(j, p), CheckScript, nil, nil)
			cancel()
			if err == nil && strings.Contains(out, "makima-ok") {
				j.path = "direct"
				if !p.Direct {
					j.path = "via relay"
				}
				r.step(j, "verify", "ok", "reached over makima, "+j.path)
				return
			}
			why = fmt.Sprintf("makima reaches it, but ssh over makima did not get in (%v)", err)
		}
		if !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			why = ctx.Err().Error()
			deadline = time.Now()
		case <-time.After(r.Poll):
		}
	}
	r.fail(j, "verify", Stayed, "on makima beside Tailscale, but not reached over it: "+why+". Tailscale is untouched")
}

// reachable says whether a machine still answers over makima, trying for a
// while: a machine that has just had Tailscale taken off it may take a moment
// to settle.
func (r *Runner) reachable(ctx context.Context, j *job, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		if p, ok := r.peers()[j.Name]; ok && p.Online {
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			out, err := r.SSH.Run(cctx, r.meshTarget(j, p), CheckScript, nil, nil)
			cancel()
			if err == nil && strings.Contains(out, "makima-ok") {
				return true
			}
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(r.Poll):
		}
	}
}

// retireRemote takes Tailscale off a machine, over makima.
func (r *Runner) retireRemote(ctx context.Context, j *job) {
	r.step(j, "remove", "running", "removing Tailscale, over makima")
	p := r.peers()[j.Name]
	script, stdin := asRoot(j, commandLine(Makima, []string{"migrate", "retire"}), nil)
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	out, err := r.SSH.Run(cctx, r.meshTarget(j, p), script, stdin, nil)
	cancel()
	var rt Retired
	if err == nil {
		err = json.Unmarshal([]byte(lastJSON(out)), &rt)
	}
	if err != nil {
		detail := "on makima" + j.pathNote() + "; Tailscale could not be removed (" + err.Error() + ") and is still running beside it"
		r.set(j, Both, detail)
		r.step(j, "remove", "failed", detail)
		return
	}
	if !r.reachable(ctx, j, time.Minute) {
		rt.Notes = append(rt.Notes, "makima did not answer again straight after Tailscale came off — if it stays that way, 'makima down' and 'makima up' there")
	}
	r.settle(j, rt)
}

// retireLocal takes Tailscale off this machine.
func (r *Runner) retireLocal(ctx context.Context, j *job) {
	r.step(j, "remove", "running", "removing Tailscale")
	out, err := r.Elevate(ctx, Action{Kind: "migrate-retire"})
	var rt Retired
	if err == nil {
		err = json.Unmarshal([]byte(lastJSON(out)), &rt)
	}
	if err != nil {
		detail := "on makima; Tailscale could not be removed here (" + err.Error() + ") and is still running beside it"
		r.set(j, Both, detail)
		r.step(j, "remove", "failed", detail)
		return
	}
	r.settle(j, rt)
}

// settle records a machine that lost Tailscale.
func (r *Runner) settle(j *job, rt Retired) {
	detail := "on makima" + j.pathNote() + "; Tailscale removed"
	if !rt.Removed {
		detail = "on makima" + j.pathNote() + "; there was no Tailscale left to remove"
	}
	r.mu.Lock()
	r.outcomes[j.ID].Notes = rt.Notes
	r.mu.Unlock()
	r.set(j, Moved, detail)
	r.step(j, "remove", "ok", detail)
}

func (j *job) pathNote() string {
	if j.path == "" {
		return ""
	}
	return ", " + j.path
}

// meshTarget is where a machine is reached over makima: its makima address,
// through ordinary SSH with the host key Tailscale published for it, or
// through makima's own SSH server where that is all there is.
func (r *Runner) meshTarget(j *job, p MeshPeer) Target {
	t := Target{Addr: p.Address, User: j.Facts.User}
	if j.mesh {
		t.Port = 2222
	} else {
		_ = r.SSH.Pin(p.Address, j.HostKeys)
	}
	return t
}

func (r *Runner) finish(res Result, ch Choice) Result {
	res.OK = res.Error == ""
	want := Moved
	if !ch.Remove {
		want = Both
	}
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
		if o.Outcome != want {
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
	return strings.TrimSpace(r.Pubkeys())
}

func (r *Runner) peers() map[string]MeshPeer {
	if r.Peers == nil {
		return nil
	}
	return r.Peers()
}

// live is the jobs still in the run.
func (r *Runner) live(jobs []*job) []*job {
	var out []*job
	for _, j := range jobs {
		if !r.gone(j) {
			out = append(out, j)
		}
	}
	return out
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

// list joins names for a sentence.
func list(names []string) string {
	if len(names) <= 1 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
