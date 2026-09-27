package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/supervise"
)

// resetCmd puts makima on this machine back the way a fresh install leaves
// it: on no network, holding none, with nothing of an old one left behind to
// trip over — no keys, no server state, no registration that starts something
// at the next boot.
//
// What makima is stays: the binaries, the app, the sudoers rule the app wrote.
// Taking those away as well is `make uninstall` — which needs a checkout, and
// a machine installed from a release has none, yet still has to be able to
// start over.
func resetCmd(args []string) error {
	fs := flag.NewFlagSet("reset", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	yes := fs.Bool("yes", false, "go ahead without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("reset takes no arguments, and was given %q", fs.Arg(0))
	}
	if err := mustBeRoot(); err != nil {
		return err
	}

	r := surveyReset(defaultResetPaths(*path))
	if err := r.refusal(); err != nil {
		return err
	}
	daemons := []resetDaemon{
		{proc: daemonFor(*path), name: "the tunnel",
			stopped: "Stopped the tunnel, and put the interface, routes, resolver and firewall back."},
		{proc: controlDaemon(), name: "the network's server"},
		// Found by its port, which is STUN's and TURN's too: something else
		// answering there is not the relay, and not the reset's to stop.
		{proc: relayDaemon(), name: "the relay", byPort: true},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if len(r.doomed) == 0 {
		// Stopped all the same: a registration whose files were deleted by
		// hand would still start something at the next boot.
		if err := stopAll(ctx, daemons); err != nil {
			return err
		}
		fmt.Println("Nothing of makima's is on this machine to reset. It is on no network.")
		return nil
	}

	fmt.Print(r.describe())
	if !*yes {
		if !atTerminal() {
			return errors.New("reset asks before it deletes anything, and there is no terminal to ask at; pass -yes to go ahead without asking")
		}
		if !r.confirm(os.Stdin, os.Stdout) {
			fmt.Println("Nothing changed.")
			return nil
		}
	}
	fmt.Println()

	kept, err := r.run(ctx, daemons, r.leave)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("Reset. This machine is on no network: 'makima up' starts a new one, and 'makima join' joins one.")
	if kept != "" {
		fmt.Printf("A copy of the network it held is in %s, root's alone, until the machine restarts.\n", kept)
	}
	return nil
}

// resetDaemon is one of makima's long-running processes, as a reset stops it.
type resetDaemon struct {
	proc interface {
		Running() bool
		Stop(ctx context.Context, wait time.Duration) error
	}
	name    string
	stopped string // said once it stops, when it was running; "Stopped <name>." otherwise
	byPort  bool   // found by a TCP port, where something else may be answering
}

// stopAll stops each daemon, and unregisters it so nothing starts at boot.
func stopAll(ctx context.Context, daemons []resetDaemon) error {
	for _, d := range daemons {
		was := d.proc.Running()
		err := d.proc.Stop(ctx, stopWait)
		switch {
		case err != nil && d.byPort && errors.Is(err, supervise.ErrNoProcess):
			fmt.Printf("Something that is not makima's answers where %s would; it is left alone.\n", d.name)
		case err != nil:
			return err
		case was && d.stopped != "":
			fmt.Println(d.stopped)
		case was:
			fmt.Printf("Stopped %s.\n", d.name)
		}
	}
	return nil
}

// run does the reset, in an order that keeps a failure harmless for as long as
// it can: everything stopped, then the held network copied aside — and until
// both have worked, the machine is still on its network with nothing deleted.
// Only then is the server asked to forget it, and the files deleted.
//
// The tunnel stops before the server is asked, too: the daemon puts the
// interface, routes, resolver and firewall back on its way out, which it
// cannot once its config is gone, and with it stopped the request goes out
// over the machine's own network rather than into a tunnel, or through an exit
// node, that is about to disappear.
func (r *resetState) run(ctx context.Context, daemons []resetDaemon, leave func(context.Context)) (string, error) {
	if err := stopAll(ctx, daemons); err != nil {
		return "", fmt.Errorf("%w; nothing was deleted, and this machine has not left its network", err)
	}

	// Again, now that nothing is running: stopping writes and removes files
	// of its own.
	r.list()
	kept, err := r.copyAside()
	if err != nil {
		return "", fmt.Errorf("keep a copy of the network before deleting it: %w; nothing was deleted, and this machine has not left its network", err)
	}

	if r.leaves() {
		leave(ctx)
	}
	if err := r.remove(); err != nil {
		return kept, err
	}
	fmt.Println("Deleted everything it listed.")
	return kept, nil
}

// resetPaths are the places a reset clears. They are fields, not the
// constants themselves, so a test can point them at a temporary directory.
type resetPaths struct {
	// config is the node's config. With the default path its whole directory
	// goes, since everything in /etc/makima is makima's; with one given by
	// -config, only the files makima puts beside it, since the directory may
	// be anybody's.
	config   string
	wholeDir bool

	run      string // the servers' state, pid files, and the inbox of a machine with no owner
	log      string
	resolver string // macOS's per-domain resolver files
	tmp      string // where the copy of a held network is kept

	// operator is the person's own makima directory, where the network
	// lock's signing key lives. It is not deleted: the key may be trusted by
	// a network that outlives this machine, and a lost one is `lock forget`
	// on the server and `lock reset` on every machine. It is named, so that
	// keeping it is not a surprise.
	operator string
}

func defaultResetPaths(config string) resetPaths {
	return resetPaths{
		config:   config,
		wholeDir: config == conf.DefaultPath,
		run:      runDir,
		log:      logDir,
		resolver: "/etc/resolver",
		tmp:      "/tmp",
		operator: operatorDir(),
	}
}

// operatorDir is ~/.config/makima for the person running this, or "" when
// there is no telling who that is.
func operatorDir() string {
	u := invokerFromEnv()
	if u == nil || u.HomeDir == "" {
		return ""
	}
	return filepath.Join(u.HomeDir, ".config", "makima")
}

// inboxName is the directory in the run directory that files arrive in when a
// machine has no owner — see cmd/makimad/inbox.go. They are the person's, not
// makima's, and a reset leaves them where they are.
const inboxName = "inbox"

// nodeFiles is what makima keeps of this machine's own: its config and the
// copies of it an upgrade left, the daemon's sockets, and the update record.
func (p resetPaths) nodeFiles() []string {
	if p.wholeDir {
		return existing(filepath.Dir(p.config))
	}
	files := []string{p.config, filepath.Join(filepath.Dir(p.config), "update.json")}
	baks, _ := filepath.Glob(p.config + ".v*.bak")
	files = append(files, baks...)

	var out []string
	for _, f := range files {
		if fi, err := os.Lstat(f); err == nil && fi.Mode().IsRegular() {
			out = append(out, f)
		}
	}
	for _, sock := range []string{localapi.SocketPath(p.config), localapi.GUISocketPath(p.config)} {
		if fi, err := os.Lstat(sock); err == nil && fi.Mode()&fs.ModeSocket != 0 {
			out = append(out, sock)
		}
	}
	return out
}

// runFiles is everything in the run directory — the network's server, the
// relay, pid files, the server's port — or the directory itself when there
// is no inbox with anything in it to keep.
func (p resetPaths) runFiles() []string {
	entries, err := os.ReadDir(p.run)
	if err != nil {
		return nil
	}
	keep := false
	var out []string
	for _, e := range entries {
		full := filepath.Join(p.run, e.Name())
		if e.Name() == inboxName {
			if inside, _ := os.ReadDir(full); len(inside) > 0 {
				keep = true
				continue
			}
		}
		out = append(out, full)
	}
	if !keep {
		return []string{p.run}
	}
	return out
}

// resolverFiles are the per-domain resolver files makima wrote. The daemon
// takes its own away when it stops; one that died leaves it pointing at a
// nameserver that is gone.
func (p resetPaths) resolverFiles() []string {
	entries, err := os.ReadDir(p.resolver)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		full := filepath.Join(p.resolver, e.Name())
		if e.Type().IsRegular() && managedByMakima(full) {
			out = append(out, full)
		}
	}
	return out
}

// managedByMakima says whether a resolver file is one makima wrote: they say
// so on their first line.
func managedByMakima(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	return strings.HasPrefix(line, "# Managed by makima")
}

// existing is the paths that are there.
func existing(paths ...string) []string {
	var out []string
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// resetState is what a reset found on this machine, before it touches any of
// it.
type resetState struct {
	paths resetPaths

	// node is the network this machine is on; nil when it is on none, or its
	// config could not be read — which a reset deletes all the same.
	node *conf.File

	// held is the network this machine's server holds; nil when it holds
	// none. heldUnread is a server state that is there and could not be read,
	// so nobody can say who else is on it.
	held       *control.State
	heldUnread bool

	// doomed is every path the reset deletes; backup is the part of it
	// copied aside first, when this machine holds a network.
	doomed []string
	backup []string
}

func surveyReset(p resetPaths) *resetState {
	r := &resetState{paths: p}
	if f, err := conf.Load(p.config); err == nil {
		r.node = f
	}
	if b, err := os.ReadFile(filepath.Join(p.run, filepath.Base(serverStatePath))); err == nil {
		var st control.State
		if json.Unmarshal(b, &st) == nil {
			r.held = &st
		} else {
			r.held = &control.State{}
			r.heldUnread = true
		}
	}

	r.list()
	return r
}

// list finds what to delete, and what of it to copy aside first. Done once to
// say what the reset will do, and again once everything has stopped, for
// whatever the stopping itself wrote.
func (r *resetState) list() {
	p := r.paths
	runFiles := p.runFiles()
	var nodeFiles []string
	if p.wholeDir || r.node != nil {
		// A chosen config makima cannot read as its own is somebody else's
		// file — see refusal — and so is what is beside it.
		nodeFiles = p.nodeFiles()
	}
	r.doomed = slices.Concat(nodeFiles, runFiles, existing(p.log), p.resolverFiles())
	r.backup = nil
	if r.held != nil {
		r.backup = slices.Concat(nodeFiles, runFiles)
	}
}

// refusal is why a reset will not go ahead here, or nil.
//
// A config somewhere of the person's choosing that is not makima's is not
// deleted, nor anything beside it: -config naming a directory, or the wrong
// file, would otherwise take it with everything in it. And a directory of
// makima's that is a symlink is not followed — deleting the link would leave
// the network's keys where it points while saying they were gone, and
// deleting where it points is deleting wherever somebody pointed it.
func (r *resetState) refusal() error {
	p := r.paths
	if !p.wholeDir && r.node == nil {
		if _, err := os.Lstat(p.config); err == nil {
			return fmt.Errorf("%s is not a makima config, so reset leaves it, and everything beside it, alone", p.config)
		}
	}
	dirs := []string{p.run, p.log}
	if p.wholeDir {
		dirs = append(dirs, filepath.Dir(p.config))
	}
	for _, d := range dirs {
		if fi, err := os.Lstat(d); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			to, _ := os.Readlink(d)
			return fmt.Errorf("%s is a symlink to %s, which reset does not follow; delete what is there by hand, or put the directory back where it was", d, to)
		}
	}
	return nil
}

// ownNetwork says whether the network this machine is on is the one it
// holds.
func (r *resetState) ownNetwork() bool {
	return r.node != nil && r.held != nil && !r.heldUnread &&
		r.node.ServerKey == r.held.ServerKey.Public()
}

// leaves says whether there is a server elsewhere to ask to forget this
// machine. One this machine holds is going away with it, and a mesh with no
// server has nobody to ask.
func (r *resetState) leaves() bool {
	return r.node != nil && r.node.Managed() && !r.ownNetwork()
}

// others are the machines on the network this machine holds, itself aside.
func (r *resetState) others() []string {
	if r.held == nil {
		return nil
	}
	var out []string
	for _, n := range r.held.Nodes {
		if r.node != nil && n.MachineKey == r.node.MachineKey.Public() {
			continue
		}
		out = append(out, n.Name)
	}
	return out
}

// strands says whether a reset here takes a network away from other
// machines, or cannot rule it out.
func (r *resetState) strands() bool {
	return r.held != nil && (r.heldUnread || len(r.others()) > 0)
}

// describe is what a reset will do, said before it does any of it.
func (r *resetState) describe() string {
	var b strings.Builder
	row := func(verb, text string) { fmt.Fprintf(&b, "  %-8s %s\n", verb, text) }

	b.WriteString("This puts makima on this machine back the way a fresh install leaves it.\n\n")
	if n := r.node; n != nil {
		who := n.Self.Name
		if a, err := n.Self.Addr(); err == nil {
			who += " (" + a.String() + ")"
		}
		switch {
		case r.leaves():
			row("leaves", fmt.Sprintf("the network at %s, where it is %s, and asks that network's server to forget it", n.LoginServer, who))
		case !n.Managed():
			row("leaves", fmt.Sprintf("its mesh with no server, where it is %s; the machines it was paired with keep listing it until it is removed there", who))
		}
	}
	if r.held != nil {
		switch others := r.others(); {
		case r.heldUnread:
			row("ends", "the network this machine holds; every machine on it loses its server and has to join a new one")
		case len(others) == 0:
			row("ends", "the network this machine holds, which no other machine is on")
		case len(others) == 1:
			row("ends", fmt.Sprintf("the network this machine holds: %s loses its server, and has to join a new network", others[0]))
		default:
			row("ends", fmt.Sprintf("the network this machine holds: %s lose their server, and each has to join a new network", nameList(others)))
		}
	}
	row("stops", "the tunnel, and whatever of makima's starts at boot")
	for i, p := range r.doomed {
		verb := ""
		if i == 0 {
			verb = "deletes"
		}
		row(verb, p)
	}
	row("keeps", "makima itself and the app, and files other machines sent here")
	if r.paths.operator != "" && len(existing(filepath.Join(r.paths.operator, "signing.key"))) > 0 {
		row("", "the network lock's signing key, in "+r.paths.operator)
	}
	b.WriteString("\n")
	return b.String()
}

// nameList is names as a sentence: "a", "a and b", "a, b and c".
func nameList(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// confirm asks. A yes is enough for this machine alone; ending a network that
// other machines are on takes the word, since a stray y there is every
// machine on it joining again.
func (r *resetState) confirm(in io.Reader, out io.Writer) bool {
	answer := func() string {
		s, _ := bufio.NewReader(in).ReadString('\n')
		return strings.TrimSpace(s)
	}
	if r.strands() {
		fmt.Fprint(out, `Other machines are on the network this one holds. Type "reset" to go ahead: `)
		return answer() == "reset"
	}
	fmt.Fprint(out, "Reset this machine? [y/N] ")
	a := strings.ToLower(answer())
	return a == "y" || a == "yes"
}

// leave asks the network's server to forget this machine, so the others drop
// it now rather than list it as offline for good.
//
// It never stops the reset. A machine away from home, or on a network whose
// server is gone, still has to be able to start over; once its keys are
// deleted it can never ask again, so what to run instead is said here.
func (r *resetState) leave(ctx context.Context) {
	n := r.node
	c := control.NewClient(n.LoginServer, n.ServerKey, n.MachineKey)
	c.SetAlternates(n.ControlURLs)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	forget := "makima-server forget -name " + strconv.Quote(n.Self.Name)
	if n.Self.ID != 0 {
		forget = fmt.Sprintf("makima-server forget -id %d", n.Self.ID)
	}
	name, err := c.Leave(ctx)
	switch {
	case err == nil && name != "":
		fmt.Println("The network's server forgot this machine, and the others drop it now.")
	case err == nil:
		fmt.Println("The network's server had already forgotten this machine.")
	case errors.Is(err, control.ErrNoLeave):
		fmt.Printf("The network's server runs a makima from before machines could leave on their own, so the others will list this one as offline until, on the machine holding the network:\n  %s\n", forget)
	default:
		fmt.Printf("Could not have the network's server forget this machine (%v), so the others will list it as offline until, on the machine holding the network:\n  %s\n", err, forget)
	}
}

// copyAside copies a held network to the temporary directory, root's alone —
// a reset run on the wrong machine is otherwise every machine on the network
// joining again — and says where. Nothing, and "", for a machine holding
// none.
func (r *resetState) copyAside() (string, error) {
	if len(r.backup) == 0 {
		return "", nil
	}
	dir := filepath.Join(r.paths.tmp, "makima-reset-"+time.Now().Format("20060102-150405"))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	for _, p := range r.backup {
		if err := copyTree(p, filepath.Join(dir, p)); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// remove deletes everything the reset listed, going on past what it cannot
// delete so that as much as possible is gone, and saying what that was.
func (r *resetState) remove() error {
	var failed []string
	for _, p := range r.doomed {
		if err := os.RemoveAll(p); err != nil {
			failed = append(failed, err.Error())
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not delete everything: %s", strings.Join(failed, "; "))
	}
	return nil
}

// copyTree copies the regular files and directories under src to dst, modes
// kept. Sockets are left behind: they mean nothing once their server is gone.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		case info.Mode().IsRegular():
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			return copyFile(p, target, info.Mode().Perm())
		}
		return nil
	})
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
