package migrate

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Access is how the migration gets a shell on a machine.
type Access struct {
	// User is who to log in as; empty means whatever ssh would pick, which
	// honours ~/.ssh/config.
	User string `json:"user,omitempty"`

	// AuthURL is set while Tailscale SSH is waiting for a browser check.
	AuthURL string `json:"auth_url,omitempty"`

	Error string `json:"error,omitempty"`
}

// Candidate is one machine and what the scan made of it.
type Candidate struct {
	Machine
	Facts  *Facts  `json:"facts,omitempty"`
	Access *Access `json:"access,omitempty"`

	// Eligible says the migration can move this machine. Why says why not,
	// or — for an eligible machine — anything worth knowing first.
	Eligible bool   `json:"eligible"`
	Why      string `json:"why,omitempty"`

	// NeedsPassword is a machine whose sudo asks for one. The app asks the
	// person for it before the run, and it goes to that machine's sudo and
	// nowhere else.
	NeedsPassword bool `json:"needs_password,omitempty"`

	// Public and Reach are addresses: the one the internet can reach, if
	// any, and the one the rest would use to reach this machine if it held
	// the network.
	Public string `json:"public,omitempty"`
	Reach  string `json:"reach,omitempty"`

	// Score ranks machines as places to hold the network, and Pitch is the
	// one line that explains the ranking to a person.
	Score int    `json:"score"`
	Pitch string `json:"pitch,omitempty"`

	// Checking is a machine the scan has not finished with. Every machine is
	// announced this way first, so one waiting on a browser approval is on
	// screen, with its button, while it waits.
	Checking bool `json:"checking,omitempty"`
}

// Plan is the scan's answer: every machine, and which should hold the network.
type Plan struct {
	Tailnet    string      `json:"tailnet"`
	Machines   []Candidate `json:"machines"`
	Controller string      `json:"controller,omitempty"`
	Advice     string      `json:"advice,omitempty"`
	Version    string      `json:"version"`
}

// Find returns the candidate with an ID.
func (p *Plan) Find(id string) (*Candidate, bool) {
	for i := range p.Machines {
		if p.Machines[i].ID == id {
			return &p.Machines[i], true
		}
	}
	return nil, false
}

// Event is one line of progress, for the app to draw.
type Event struct {
	Type    string     `json:"type"`
	Machine string     `json:"machine,omitempty"`
	Step    string     `json:"step,omitempty"`
	State   string     `json:"state,omitempty"`
	Detail  string     `json:"detail,omitempty"`
	URL     string     `json:"url,omitempty"`
	Cand    *Candidate `json:"candidate,omitempty"`
	Plan    *Plan      `json:"plan,omitempty"`
	Result  *Result    `json:"result,omitempty"`
}

// Scanner is what a scan needs from the outside world.
type Scanner struct {
	SSH     Shell
	Emit    func(Event)
	Version string

	// Local runs a script on this machine. A variable so tests do not have
	// to probe the machine they run on.
	Local func(ctx context.Context, script string) (string, error)
}

// RunLocal runs a script here with sh.
func RunLocal(ctx context.Context, script string) (string, error) {
	out, err := exec.CommandContext(ctx, "sh", "-c", script).Output()
	return string(out), err
}

// Scan looks at every machine on the tailnet and changes none of them.
func Scan(ctx context.Context, tn *Tailnet, sc Scanner) Plan {
	if sc.Local == nil {
		sc.Local = RunLocal
	}
	emit := func(e Event) {
		if sc.Emit != nil {
			sc.Emit(e)
		}
	}

	all := tn.All()
	cands := make([]Candidate, len(all))
	for _, m := range all {
		early := Candidate{Machine: m, Checking: true}
		emit(Event{Type: "machine", Machine: m.ID, Cand: &early})
	}
	var wg sync.WaitGroup
	for i, m := range all {
		cands[i] = Candidate{Machine: m}
		wg.Add(1)
		go func(c *Candidate) {
			defer wg.Done()
			examine(ctx, c, sc, emit)
			judge(c)
			emit(Event{Type: "machine", Machine: c.ID, Cand: c})
		}(&cands[i])
	}
	wg.Wait()

	p := Plan{Tailnet: tn.Name, Machines: cands, Version: sc.Version}
	rank(&p)
	return p
}

// examine gathers facts about one machine, here or over SSH.
func examine(ctx context.Context, c *Candidate, sc Scanner, emit func(Event)) {
	if !supportedOS(c.OS) || (!c.Local && (!c.Online || c.Shared)) {
		return
	}

	if c.Local {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		out, err := sc.Local(cctx, ProbeScript)
		if f, perr := ParseFacts(out); perr == nil {
			c.Facts = &f
		} else if err != nil {
			c.Access = &Access{Error: err.Error()}
		}
		return
	}

	if sc.SSH == nil {
		c.Access = &Access{Error: "there is no ssh client here"}
		return
	}
	addr := c.IPv4()
	_ = sc.SSH.Pin(addr, c.HostKeys)

	// Whatever ssh would do on its own first — the person's config may well
	// name the right user already — then root, which is who most servers
	// are reached as.
	var last error
	for _, user := range []string{"", "root"} {
		a := &Access{User: user}
		c.Access = a
		out, err := runWaitingForAuth(ctx, sc.SSH, Target{Addr: addr, User: user}, ProbeScript, nil, func(u string) {
			a.AuthURL = u
			emit(Event{Type: "auth", Machine: c.ID, URL: u})
		})
		if a.AuthURL != "" && err != nil {
			// Waited out. Once approved in the browser the next attempt
			// goes straight through, so it is left for a rescan.
			a.Error = "Tailscale SSH wants this login approved in a browser"
			return
		}
		if err == nil {
			f, perr := ParseFacts(out)
			if perr != nil {
				a.Error = perr.Error()
				return
			}
			a.AuthURL = ""
			c.Facts = &f
			return
		}
		last = err
		if errors.Is(err, ErrUnreachable) {
			break
		}
	}
	msg := last.Error()
	if errors.Is(last, ErrDenied) {
		msg = "SSH refused this Mac's keys, as you and as root — turn on Tailscale SSH there (tailscale set --ssh), or add your key to its authorized_keys"
	}
	c.Access.Error = msg
}

// runWaitingForAuth runs a command with a short deadline, unless Tailscale SSH
// stops to ask for a browser check — then it waits the few minutes it takes a
// person to notice and click, and the same session goes through once they do.
func runWaitingForAuth(ctx context.Context, s Shell, t Target, script string, stdin []byte, onAuth func(string)) (string, error) {
	return runWaiting(ctx, s, t, script, stdin, 25*time.Second, onAuth)
}

func runWaiting(ctx context.Context, s Shell, t Target, script string, stdin []byte, short time.Duration, onAuth func(string)) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	var mu sync.Mutex
	asked := false
	timer := time.AfterFunc(short, func() {
		mu.Lock()
		defer mu.Unlock()
		if !asked {
			cancel()
		}
	})
	defer timer.Stop()
	return s.Run(cctx, t, script, stdin, func(u string) {
		mu.Lock()
		first := !asked
		asked = true
		mu.Unlock()
		if first && onAuth != nil {
			onAuth(u)
		}
	})
}

func supportedOS(tsOS string) bool {
	switch strings.ToLower(tsOS) {
	case "linux", "macos", "darwin":
		return true
	}
	return false
}

// judge decides whether a machine can be moved, and fills in why not.
func judge(c *Candidate) {
	switch {
	case !supportedOS(c.OS):
		c.Why = fmt.Sprintf("makima does not run on %s yet — it stays on Tailscale", displayOS(c.OS))
		return
	case c.Shared:
		c.Why = "shared into your tailnet by someone else — it is theirs to move"
		return
	case !c.Local && !c.Online:
		c.Why = "offline — turn it on and scan again to bring it along"
		return
	case c.Access != nil && c.Access.Error != "" && c.Facts == nil:
		c.Why = c.Access.Error
		return
	case c.Facts == nil:
		c.Why = "could not be examined"
		return
	}

	f := c.Facts
	switch {
	case !f.Supported():
		c.Why = fmt.Sprintf("there is no makima build for %s/%s", f.OS, f.Arch)
		return
	case f.Sudo == "none":
		c.Why = fmt.Sprintf("%s cannot become root there (no sudo)", f.User)
		return
	}

	c.Eligible = true
	c.NeedsPassword = f.Sudo == "password" && !c.Local
	if a := f.Public(); a.IsValid() {
		c.Public = a.String()
	}
	if a := f.Reach(); a.IsValid() {
		c.Reach = a.String()
	}
	if f.Member && !f.Holds {
		c.Why = "already on a makima network — it can only move to that network's machine"
	}
	if f.Via == "tailscale" && !f.OpenSSH {
		c.Why = "reached through Tailscale SSH with no sshd behind it — makima's own SSH server takes over, with your keys"
	}
}

func displayOS(s string) string {
	switch strings.ToLower(s) {
	case "ios":
		return "iPhone or iPad"
	case "android":
		return "Android"
	case "windows":
		return "Windows"
	case "":
		return "that system"
	}
	return s
}

// rank scores the eligible machines as homes for the network.
//
// What matters, in order: a public address, which is the only thing that lets
// devices anywhere reach the network and lets it relay for the ones that
// cannot reach each other. Then staying on — a server over a laptop that
// sleeps in a bag. Then already holding a makima network, because the devices
// on it already trust it; it counts for less than either, since the network
// being held is often somebody's first try, on a laptop.
func rank(p *Plan) {
	for i := range p.Machines {
		c := &p.Machines[i]
		if !c.Eligible || c.Facts == nil {
			continue
		}
		var why []string
		if c.Facts.Holds {
			c.Score += 20
			why = append(why, "already holds a makima network")
		}
		if c.Public != "" {
			c.Score += 60
			why = append(why, "has a public address, so devices anywhere can reach it, and it can relay for them")
		}
		if c.Facts.OS == "linux" {
			c.Score += 10
			if c.Public == "" {
				why = append(why, "a server that stays on")
			}
		}
		if laptop(c) {
			c.Score -= 25
		} else if c.Facts.OS == "darwin" && len(why) == 0 {
			why = append(why, "a desktop that stays on")
		}
		if c.Local {
			c.Score += 5
		}
		if c.Reach == "" {
			c.Score -= 50
		}
		if len(why) == 0 {
			if laptop(c) {
				why = append(why, "a laptop: the network is only up while it is awake and at home")
			} else {
				why = append(why, "can hold the network for devices on its own network")
			}
		}
		c.Pitch = strings.Join(why, "; ")
	}

	best := -1 << 30
	for _, c := range p.Machines {
		if c.Eligible && c.Score > best {
			best, p.Controller = c.Score, c.ID
		}
	}

	anyPublic := false
	for _, c := range p.Machines {
		if c.Eligible && c.Public != "" {
			anyPublic = true
		}
	}
	if p.Controller != "" && !anyPublic {
		p.Advice = "None of these machines has a public address, so the network only reaches devices that can get to the one holding it — normally, the ones on the same home network. Each device is checked before anything on it changes; one that cannot reach it stays on Tailscale. A cheap VPS with makima on it fixes this for good."
	}
}

func laptop(c *Candidate) bool {
	n := strings.ToLower(c.Host + " " + c.Name)
	return strings.Contains(n, "macbook") || strings.Contains(n, "laptop") || strings.Contains(n, "thinkpad")
}

// Sorted returns the plan's machines with the eligible first, the recommended
// controller at the top.
func (p *Plan) Sorted() []Candidate {
	out := append([]Candidate(nil), p.Machines...)
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].ID == p.Controller) != (out[j].ID == p.Controller) {
			return out[i].ID == p.Controller
		}
		if out[i].Eligible != out[j].Eligible {
			return out[i].Eligible
		}
		return out[i].Score > out[j].Score
	})
	return out
}
