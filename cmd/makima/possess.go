package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/dnsserver"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/sshd"
)

// `makima ssh`, and `makima possess` for the same thing.
//
// Sugar over the system's ssh client, and deliberately so: sshd already
// listens on every address, so a mesh peer is reachable at its name the moment
// the tunnel is up and `ssh desktop.makima` has always worked. What this
// removes is having to know the suffix, having to remember whether the machine
// was added as "desktop" or "desktop.local" — and now, having to know which
// account on it your keys open, and having ssh call a machine an impostor
// because another one had its address last month.

// sshCmd opens a shell on a peer.
func sshCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("which machine? (try: makima possess desktop — 'makima status' lists them)")
	}

	target := args[0]
	rest := args[1:]

	account := ""
	if u, host, ok := strings.Cut(target, "@"); ok {
		account, target = u, host
	}

	p, err := resolvePeer(target)
	if err != nil {
		return err
	}

	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return errors.New("no ssh client on this machine")
	}

	x := sshProber{ssh: ssh, p: p}
	var r route
	if account == "" {
		r, err = planRoute(target, p, x)
		if err != nil {
			return err
		}
		account, err = pickAccount(target, r, x.defaultUser())
		if err != nil {
			return err
		}
	} else if x.dial(sshd.DefaultPort) == reachOpen {
		// Named outright, so nothing is asked of the far end — except which
		// server to knock on, for which one short dial is enough.
		r.port = sshd.DefaultPort
	}

	host := p.addr
	if account != "" {
		host = account + "@" + host
	}

	args = append(append(x.options(r.port), host), rest...)
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

// farEnd is the machine at the other end, as far as this one knows it.
type farEnd struct {
	// addr is what ssh dials: the mesh address, or the name as it was given
	// when there was no daemon to ask.
	addr string

	// key is its node key, zero when the daemon could not say.
	key key.Public

	// owner is the account makima belongs to there, empty when the far end
	// has not said — or said something that could not be an account's name.
	owner string
}

// route is how a shell on a peer is reached, worked out before ssh runs.
type route struct {
	// port is makima's own server's, or 0 for the system's sshd.
	port int

	// accounts are those the person's keys open there, best first.
	accounts []sshd.Account

	// password is the account to ask a password for when no key opens any,
	// "" for whichever ssh would use by itself; note says which, before ssh
	// asks.
	password string
	note     string
}

// reach is what one dial says about a port.
type reach int

const (
	reachUnknown reach = iota // no answer in time, or an error that says nothing
	reachOpen                 // something accepted the connection
	reachRefused              // the machine answered that nothing listens there
)

// prober asks the far end the questions a route is worked out from. An
// interface so the deciding can be tested without a network or an ssh.
type prober interface {
	dial(port int) reach
	listAccounts(port int) []sshd.Account
	opens(port int, account string) bool
	defaultUser() string
	me() string
}

// planRoute decides which server to knock on and which accounts there are
// worth offering.
//
// makima's own server first, when it is running and some key of the
// person's opens an account on it: it is the one that can say exactly which.
// Otherwise the system's sshd, where the candidates are tried one key-only
// login at a time. When no key opens anything there, the password ssh asks
// for is the far end's owner's — the account makima belongs to there — rather
// than one named after whoever is sitting here, which on another person's
// machine, or simply a machine set up under another name, is an account that
// does not exist and a password that can never be right.
func planRoute(name string, p farEnd, x prober) (route, error) {
	builtIn := x.dial(sshd.DefaultPort) == reachOpen
	if builtIn {
		if list := x.listAccounts(sshd.DefaultPort); len(list) > 0 {
			return route{port: sshd.DefaultPort, accounts: list}, nil
		}
		// A makima from before the question could be asked cannot answer
		// it, but can still be tried.
		if x.opens(sshd.DefaultPort, "") {
			return route{port: sshd.DefaultPort}, nil
		}
	}

	if x.dial(22) == reachRefused {
		if builtIn {
			return route{}, keysOnly(name, p)
		}
		return route{}, noServer(name)
	}

	def, me := x.defaultUser(), x.me()
	configured := def != "" && def != me

	// Candidates in the order they are offered: the account a login lands in
	// by default, then this person's own name where it differs, then root.
	type candidate struct {
		name string
		dflt bool
	}
	var cands []candidate
	switch {
	case configured:
		// Their ssh config says who to be there, and is obeyed.
		cands = append(cands, candidate{def, true})
	case p.owner != "":
		cands = append(cands, candidate{p.owner, true}, candidate{def, false})
	default:
		cands = append(cands, candidate{def, true})
	}
	cands = append(cands, candidate{"root", false})

	seen := map[string]bool{}
	var open []sshd.Account
	for _, c := range cands {
		if c.name == "" || seen[c.name] {
			continue
		}
		seen[c.name] = true
		if x.opens(0, c.name) {
			open = append(open, sshd.Account{Name: c.name, Default: c.dflt, Root: c.name == "root"})
		}
	}
	if len(open) > 0 {
		return route{accounts: sshd.SortAccounts(open)}, nil
	}

	// No key opens anything, so ssh will ask for a password: for an account
	// that exists, and said out loud, because "Permission denied" after every
	// password does not say that the account was the problem.
	switch {
	case configured:
		return route{note: fmt.Sprintf(
			"No key of yours opens an account on %s, so it will ask for the password of %s — the account your ssh config names.",
			name, def)}, nil
	case p.owner != "":
		return route{password: p.owner, note: fmt.Sprintf(
			"No key of yours opens an account on %s yet, so it will ask for the password of %s — the account makima belongs to there.\n"+
				"Another account: makima possess NAME@%s",
			name, p.owner, name)}, nil
	default:
		return route{note: fmt.Sprintf(
			"No key of yours opens an account on %s, so it will ask for the password of %s — your name on this machine.\n"+
				"If %s knows you by another: makima possess NAME@%s",
			name, def, name, name)}, nil
	}
}

// pickAccount turns a route into the account to log in as: "" for whichever
// ssh would use by itself.
//
// One account is used, and said when it is not the obvious one; several are
// offered as a list, if there is somebody at a terminal to offer it to; none
// is the password route, said before ssh asks.
func pickAccount(name string, r route, sshDefault string) (string, error) {
	// No -l for the name ssh sends anyway: saying it again changes nothing,
	// and keeps the command as plain as the one somebody would have typed.
	asSSH := func(a string) string {
		if a == sshDefault {
			return ""
		}
		return a
	}

	switch {
	case len(r.accounts) == 0:
		if r.note != "" {
			fmt.Fprintln(os.Stderr, r.note)
		}
		return asSSH(r.password), nil

	case len(r.accounts) == 1:
		a := r.accounts[0]
		if !a.Default {
			// Saying so for the expected account would be noise on every
			// single connection; for any other it is the thing to know.
			fmt.Fprintf(os.Stderr, "Logging in as %s — the account your keys open on %s.\n", a.Name, name)
		}
		return asSSH(a.Name), nil
	}

	if !interactive() {
		a := r.accounts[0]
		fmt.Fprintf(os.Stderr, "Your keys open %d accounts on %s; using %s. Name one with %s@%s to choose.\n",
			len(r.accounts), name, a.Name, r.accounts[len(r.accounts)-1].Name, name)
		return asSSH(a.Name), nil
	}

	items := make([]menuItem, 0, len(r.accounts))
	for _, a := range r.accounts {
		items = append(items, menuItem{Label: a.Name, Note: accountNote(a)})
	}

	at, err := choose("Possess "+name+" as:", items)
	if errors.Is(err, ErrPickerCancelled) {
		// Nothing happened, and nothing should be printed about it — the
		// person who pressed escape knows what they pressed.
		os.Exit(130)
	}
	if err != nil {
		return "", err
	}
	return asSSH(r.accounts[at].Name), nil
}

// accountNote is the half-sentence beside an account in the picker.
func accountNote(a sshd.Account) string {
	switch {
	case a.Root && a.Default:
		return "the whole machine, and what makima runs sessions as"
	case a.Root:
		return "the whole machine"
	case a.Default:
		return "the account makima runs sessions as"
	}
	return ""
}

// noServer is a machine nothing on which takes ssh connections.
func noServer(name string) error {
	return fmt.Errorf("nothing on %s answers ssh. On %s, either:\n"+
		"  makima sshd -on     makima's own server, on the mesh address only\n"+
		"or switch on its system ssh server — on a Mac, Remote Login in System Settings → General → Sharing",
		name, name)
}

// keysOnly is a machine whose only ssh server is makima's, which no key of
// this person's opens: it has no passwords to fall back to.
func keysOnly(name string, p farEnd) error {
	who := "the account makima runs as there"
	if p.owner != "" {
		who = p.owner
	}
	return fmt.Errorf("makima's ssh server on %s takes keys only, and none of yours opens an account there.\n"+
		"On %s, add this machine's public key (~/.ssh/id_ed25519.pub — ssh-keygen -t ed25519 makes one) to %s's ~/.ssh/authorized_keys,\n"+
		"or switch on its system ssh server, which can take a password",
		name, name, who)
}

// sshProber is the prober that asks over the network, with the system's ssh.
type sshProber struct {
	ssh string
	p   farEnd
}

// dial is one short connection attempt. A refusal is the far end saying
// nothing listens; silence says nothing at all, since a firewall that drops
// is indistinguishable from a slow path.
func (x sshProber) dial(port int) reach {
	timeout := 700 * time.Millisecond
	if port == 22 {
		timeout = 2 * time.Second
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(x.p.addr, strconv.Itoa(port)), timeout)
	switch {
	case err == nil:
		c.Close()
		return reachOpen
	case errors.Is(err, syscall.ECONNREFUSED):
		return reachRefused
	}
	return reachUnknown
}

// listAccounts asks makima's server which accounts the person's keys open,
// in one round trip, under a username that can start no process.
func (x sshProber) listAccounts(port int) []sshd.Account {
	args := append(x.probeArgs(port), "-l", sshd.ListAccountsUser, x.p.addr, "makima-accounts")
	out, err := exec.Command(x.ssh, args...).Output()
	if err != nil {
		// Either the key opens nothing there, or the far end is an older
		// makima that does not know this username and ran it as a command.
		return nil
	}
	var list sshd.AccountList
	if err := json.Unmarshal(out, &list); err != nil {
		return nil
	}
	return list.Accounts
}

// opens reports whether a key-only login as one account works. An ordinary
// sshd cannot be asked which accounts a key opens — there is no such
// question in SSH — so this is how it is found out, a login that asks
// nothing and changes nothing.
func (x sshProber) opens(port int, account string) bool {
	args := x.probeArgs(port)
	if account != "" {
		args = append(args, "-l", account)
	}
	return exec.Command(x.ssh, append(args, x.p.addr, "true")...).Run() == nil
}

// defaultUser is the account ssh itself would use for the host, which is the
// person's own name unless their ~/.ssh/config says otherwise.
func (x sshProber) defaultUser() string {
	out, err := exec.Command(x.ssh, "-G", x.p.addr).Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if name, ok := strings.CutPrefix(line, "user "); ok {
				return strings.TrimSpace(name)
			}
		}
	}
	return x.me()
}

func (x sshProber) me() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// probeArgs are the options every probe shares: never ask for anything,
// never wait long.
func (x sshProber) probeArgs(port int) []string {
	return append([]string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"}, x.options(port)...)
}

// options are what every ssh to the peer carries, the probes and the shell
// alike: the port, and where its host key is filed.
func (x sshProber) options(port int) []string {
	var args []string
	if !x.p.key.IsZero() {
		args = append(args,
			"-o", "HostKeyAlias="+hostKeyAlias(x.p.key, port),
			"-o", "StrictHostKeyChecking=accept-new")
	}
	if port != 0 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	return args
}

// hostKeyAlias is the name a peer's host key is filed under in known_hosts:
// the machine, rather than its address.
//
// Mesh addresses are handed out again. A network started over gives
// 10.77.0.1 to whichever machine holds it now, and ssh, which files keys by
// address, then calls that machine an impostor — a warning that is false every
// time it appears here, and so teaches nothing but to delete known_hosts lines.
// The node key is the machine: WireGuard delivers a packet from this address
// only from the peer holding that key, so the host key it answers with is that
// machine's, and taken on first sight. A host key that changes while the node
// key stays the same is still the warning it should be.
//
// ssh files a key under the alias alone, whatever the port, so makima's own
// server and the system's — two host keys on one machine — get one each.
func hostKeyAlias(k key.Public, port int) string {
	alias := "makima-" + k.Hex()[:16]
	if port != 0 && port != 22 {
		alias = fmt.Sprintf("[%s]:%d", alias, port)
	}
	return alias
}

// resolvePeer turns a name into something ssh can dial, preferring the mesh
// address over the name so it works whether or not mesh DNS is on, along with
// what the mesh knows about the machine: which one it is, and whose.
func resolvePeer(name string) (farEnd, error) {
	st, ok := daemonStatus()

	// An address is already something ssh can dial, and one that is not in
	// the peer list is still the address somebody typed. In it, it is a
	// machine like any other.
	if addr, err := netip.ParseAddr(name); err == nil {
		p := farEnd{addr: name}
		if ok {
			for _, q := range st.Peers {
				if q.Address == addr {
					p = peerFrom(q)
				}
			}
		}
		return p, nil
	}

	if !ok {
		// No daemon to ask. The name may still resolve, so let ssh try rather
		// than refusing on the strength of our own unavailability.
		return farEnd{addr: name}, nil
	}

	bare := strings.TrimSuffix(name, "."+st.Domain)
	if i := dnsserver.MatchName(peerNames(st.Peers), bare); i >= 0 {
		q := st.Peers[i]
		if !q.Online {
			fmt.Fprintf(os.Stderr, "note: %s is not currently reachable on the mesh\n", q.Name)
		}
		return peerFrom(q), nil
	}

	var names []string
	for _, q := range st.Peers {
		names = append(names, q.Name)
	}
	if len(names) == 0 {
		return farEnd{}, fmt.Errorf("no peers on this mesh yet — add one with 'makima invite'")
	}
	return farEnd{}, fmt.Errorf("no machine called %q on this mesh (have: %s)", bare, strings.Join(names, ", "))
}

// peerFrom is a far end as the daemon describes it. The owner is checked here as
// well as by the server that passed it on: it is about to be handed to ssh.
func peerFrom(q localapi.PeerInfo) farEnd {
	p := farEnd{addr: q.Address.String(), key: q.Key}
	if netmap.ValidOwner(q.Owner) {
		p.owner = q.Owner
	}
	return p
}

// daemonStatus is the running daemon's view of the mesh, when there is one
// to ask.
func daemonStatus() (localapi.Status, bool) {
	c, err := localapi.Dial(localapi.SocketPath(conf.DefaultPath))
	if err != nil {
		// Not root, which is who runs ssh: the read-only socket answers this
		// just as well, and ssh must run as the person, with their keys.
		c, err = localapi.Dial(localapi.GUISocketPath(conf.DefaultPath))
	}
	if err != nil {
		return localapi.Status{}, false
	}
	st, err := c.Status()
	if err != nil {
		return localapi.Status{}, false
	}
	return st, true
}
