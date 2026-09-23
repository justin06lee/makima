package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/update"
	"github.com/justin06lee/subaru"
	"golang.org/x/term"
)

// `makima update` moves every machine in the network to a release at once.
//
// One order, given to the control plane, reaches every machine that is on
// within seconds. Each fetches the release itself from the project's GitHub
// releases, checks it against the published checksums, dry-runs the new
// daemon, swaps every copy of every program together and restarts into it —
// and puts the old version back by itself if the new one will not stay up. A
// machine that is off gets the same order when it next comes on.
//
// All of them restarting in the same few seconds is the point, not a hazard:
// a mesh that spends an afternoon half on one version and half on another is
// the thing to avoid. Each comes back on its cached netmap without waiting for
// the control plane, so the gap is a couple of seconds, and this command stays
// to show every machine arrive and then that they still reach each other.

// updateWait is how long to watch before calling whoever has not answered.
const updateWait = 4 * time.Minute

func updateCmd(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	here := fs.Bool("here", false, "update only this machine")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "usage: makima update [vX.Y.Z]\n\nmove every machine to the latest release, or to the one named\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := dialDaemon(*path)
	if err != nil {
		return err
	}
	st, err := c.Status()
	if err != nil {
		return err
	}

	tag := fs.Arg(0)
	if tag == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		latest, err := update.Latest(ctx, st.Version)
		cancel()
		if err != nil {
			return fmt.Errorf("%w\n\nreleases are cut by tagging: git tag v0.3.0 && git push origin v0.3.0\n(GitHub Actions builds and publishes it in a few minutes)", err)
		}
		tag = latest
	} else if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}

	local := *here || !st.Managed
	res, err := c.Update(tag, local)
	if errors.Is(err, localapi.ErrNoRemoteUpdates) {
		fmt.Printf("%v.\n", err)
		fmt.Printf("updating this machine only; once the control plane runs %s too, `makima update` reaches every machine.\n\n", tag)
		local = true
		res, err = c.Update(tag, true)
	}
	if errors.Is(err, update.ErrNotNewer) || (err != nil && strings.Contains(err.Error(), update.ErrNotNewer.Error())) {
		fmt.Printf("this machine already runs %s, which is not older than %s.\n", st.Version, tag)
		return nil
	}
	if err != nil {
		return err
	}

	if local {
		fmt.Printf("moving this machine to %s\n\n", res.Tag)
	} else {
		fmt.Printf("moving every machine to %s\n\n", res.Tag)
	}
	w := newUpdateWatch(*path, res.Tag, st, local)
	w.run()
	return w.verify()
}

// device is one machine being watched.
type device struct {
	name   string
	self   bool
	from   string
	online bool

	text    string
	final   bool
	moving  bool
	reached string
}

type updateWatch struct {
	config  string
	tag     string
	devices []*device
	started time.Time
	tty     bool
	drawn   int
	printed []string
	last    localapi.Status
}

func newUpdateWatch(config, tag string, st localapi.Status, local bool) *updateWatch {
	w := &updateWatch{
		config:  config,
		tag:     tag,
		started: time.Now(),
		tty:     term.IsTerminal(int(os.Stdout.Fd())),
		last:    st,
	}
	w.devices = append(w.devices, &device{name: st.Node.Name, self: true, from: st.Version, online: true})
	if !local {
		for _, p := range st.Peers {
			w.devices = append(w.devices, &device{name: p.Name, from: p.Version, online: p.Online})
		}
	}
	return w
}

// run watches until every machine that is on has arrived, failed, or had
// long enough.
func (w *updateWatch) run() {
	for {
		st, ok := w.status()
		w.judge(st, ok)
		w.draw()
		if w.done() {
			return
		}
		if time.Since(w.started) > updateWait {
			for _, d := range w.devices {
				if !d.final {
					d.text, d.final = "no answer yet — it moves once it can reach the control plane", true
				}
			}
			w.draw()
			return
		}
		time.Sleep(time.Second)
	}
}

// status asks this machine's daemon, which is itself restarting partway
// through: a failed call is that, not an error.
func (w *updateWatch) status() (localapi.Status, bool) {
	c, err := dialDaemon(w.config)
	if err != nil {
		return w.last, false
	}
	st, err := c.Status()
	if err != nil {
		return w.last, false
	}
	w.last = st
	return st, true
}

func (w *updateWatch) judge(st localapi.Status, reachable bool) {
	peers := make(map[string]localapi.PeerInfo, len(st.Peers))
	for _, p := range st.Peers {
		peers[p.Name] = p
	}
	for _, d := range w.devices {
		if d.self {
			if !reachable {
				d.text, d.final, d.moving = "restarting", false, true
				continue
			}
			w.place(d, st.Version, st.Update, true)
			continue
		}
		p, ok := peers[d.name]
		if !ok {
			d.text, d.final = "no longer in this machine's view of the network", true
			continue
		}
		w.place(d, p.Version, p.Update, p.Online || d.online)
	}
}

// place decides what one machine's line says, and whether it is finished.
func (w *updateWatch) place(d *device, version string, u *netmap.UpdateStatus, online bool) {
	elapsed := time.Since(w.started)
	switch {
	case version == w.tag:
		d.text, d.final = "✓ "+w.tag, true
	case version != "" && !subaru.Newer(w.tag, version):
		d.text, d.final = "left alone: already on "+version, true
	case u != nil && u.Tag == w.tag && u.State == netmap.UpdateFailed:
		// A failure from an earlier try of the same release is what the
		// machine reports until it tries again, which takes it a moment.
		if d.moving || elapsed > 20*time.Second {
			d.text, d.final = "✗ "+u.Error, true
		} else {
			d.text, d.final = "waiting", false
		}
	case u != nil && u.Tag == w.tag:
		d.text, d.final, d.moving = u.State, false, true
	case version == "" && !d.self:
		d.text, d.final = "runs a makima from before remote updates: run make install on it once", true
	case !online:
		d.text, d.final = "off — moves when it next comes on", true
	default:
		d.text, d.final = "waiting", false
	}
}

func (w *updateWatch) done() bool {
	for _, d := range w.devices {
		if !d.final {
			return false
		}
	}
	return true
}

func (w *updateWatch) draw() {
	width := 0
	for _, d := range w.devices {
		width = max(width, len(w.label(d)))
	}
	lines := make([]string, 0, len(w.devices))
	for _, d := range w.devices {
		from := d.from
		if from == "" {
			from = "?"
		}
		lines = append(lines, fmt.Sprintf("  %-*s  %-22s %s", width, w.label(d), from, d.text))
	}

	if !w.tty {
		// A log gets a line when a machine's line changes, not a redraw.
		if w.drawn == 0 {
			w.drawn = len(lines)
			w.printed = append([]string(nil), lines...)
			for _, l := range lines {
				fmt.Println(l)
			}
			return
		}
		for i, l := range lines {
			if l != w.printed[i] {
				fmt.Println(l)
				w.printed[i] = l
			}
		}
		return
	}
	if w.drawn > 0 {
		fmt.Printf("\033[%dA", w.drawn)
	}
	for _, l := range lines {
		fmt.Printf("\033[2K%s\n", l)
	}
	w.drawn = len(lines)
}

func (w *updateWatch) label(d *device) string {
	if d.self {
		return d.name + " (here)"
	}
	return d.name
}

// verify finishes with what the update was for: the machines that moved still
// reach each other. Sessions start again after a restart, so each gets a few
// seconds to come up before it is called unreachable.
func (w *updateWatch) verify() error {
	var arrived, failed, total int
	var check []*device
	for _, d := range w.devices {
		if !d.online {
			continue
		}
		total++
		switch {
		case strings.HasPrefix(d.text, "✓"):
			arrived++
			if !d.self {
				check = append(check, d)
			}
		case strings.HasPrefix(d.text, "✗"):
			failed++
		}
	}
	fmt.Printf("\n%d of %d machines that are on now run %s", arrived, total, w.tag)
	if failed > 0 {
		fmt.Printf("; %d could not update and kept the version they had", failed)
	}
	fmt.Println(".")

	if len(check) == 0 {
		return nil
	}
	fmt.Println("\nfrom here, after the restart:")
	deadline := time.Now().Add(20 * time.Second)
	for {
		pending := false
		for _, d := range check {
			if d.reached != "" {
				continue
			}
			c, err := dialDaemon(w.config)
			if err != nil {
				pending = true
				continue
			}
			p, err := c.Ping(d.name)
			switch {
			case err != nil:
				pending = true
			case p.Direct:
				d.reached = p.Path
				if p.Latency > 0 {
					d.reached += fmt.Sprintf(" (%s)", p.Latency.Round(time.Millisecond))
				}
			case p.RelayLatency > 0:
				d.reached = fmt.Sprintf("through the relay (%s)", p.RelayLatency.Round(time.Millisecond))
			default:
				pending = true
			}
		}
		if !pending || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}

	var lost []string
	for _, d := range check {
		reached := d.reached
		if reached == "" {
			reached = "not reached yet"
			lost = append(lost, d.name)
		}
		fmt.Printf("  %-22s %s\n", d.name, reached)
	}
	if len(lost) > 0 {
		return fmt.Errorf("%s updated but %s not answering from here yet — `makima ping %s` watches for it",
			strings.Join(lost, ", "), plural(len(lost), "is", "are"), lost[0])
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
