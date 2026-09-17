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
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/sshd"
)

// `makima ssh`, and `makima possess` for the same thing.
//
// Sugar over the system's ssh client, and deliberately so: sshd already
// listens on every address, so a mesh peer is reachable at its name the moment
// the tunnel is up and `ssh desktop.makima` has always worked. What this
// removes is having to know the suffix, having to remember whether the machine
// was added as "desktop" or "desktop.local" — and now, having to know which
// account on it your keys open.

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

	host, err := resolvePeer(target)
	if err != nil {
		return err
	}

	// Prefer the far end's built-in server when it has one. Probed rather
	// than advertised because it has to work in every mode — a serverless
	// pairing carries no service list, and a peer that switched its server on
	// a minute ago has not re-registered anywhere.
	var extra []string
	port := 0
	if builtInSSH(host) {
		port = sshd.DefaultPort
		extra = []string{"-p", strconv.Itoa(port)}
	}

	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return errors.New("no ssh client on this machine")
	}

	if account == "" {
		account, err = chooseAccount(ssh, target, host, port)
		if err != nil {
			return err
		}
	}
	if account != "" {
		host = account + "@" + host
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

// chooseAccount decides which account to log in as when none was named.
//
// One of three answers, in the order they cost anything:
//
//	one account   use it, and say so rather than silently picking
//	several       ask, if there is somebody at a terminal to ask
//	none found    hand over to ssh unchanged, which is what happens when the
//	              far end is an ordinary sshd nobody's key opens — it will ask
//	              for a password, exactly as it always did
func chooseAccount(ssh, name, host string, port int) (string, error) {
	accounts := accountsOn(ssh, host, port)

	switch {
	case len(accounts) == 0:
		return "", nil

	case len(accounts) == 1:
		a := accounts[0]
		if a.Default {
			// The account ssh would have picked anyway. Saying so would be
			// noise on every single connection.
			return "", nil
		}
		fmt.Fprintf(os.Stderr, "Logging in as %s — the account your keys open on %s.\n", a.Name, name)
		return a.Name, nil
	}

	if !interactive() {
		a := accounts[0]
		fmt.Fprintf(os.Stderr, "Your keys open %d accounts on %s; using %s. Name one with %s@%s to choose.\n",
			len(accounts), name, a.Name, accounts[len(accounts)-1].Name, name)
		return a.Name, nil
	}

	items := make([]menuItem, 0, len(accounts))
	for _, a := range accounts {
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
	return accounts[at].Name, nil
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

// accountsOn is every account on a machine the person's keys open.
//
// Asked of makima's own server where there is one: it knows every local
// account and which of them each key opens, and answers in one round trip
// under a username that can start no process.
//
// An ordinary sshd cannot be asked — there is no such question in SSH — so
// there the candidates are tried instead, which is two key-only logins that
// ask nothing and change nothing.
func accountsOn(ssh, host string, port int) []sshd.Account {
	if port == sshd.DefaultPort {
		if list, ok := askAccounts(ssh, host, port); ok {
			return list
		}
	}
	return probeAccounts(ssh, host, port)
}

// askAccounts asks makima's server directly.
func askAccounts(ssh, host string, port int) ([]sshd.Account, bool) {
	args := append(sshProbeArgs(port), "-l", sshd.ListAccountsUser, host, "makima-accounts")
	cmd := exec.Command(ssh, args...)
	out, err := cmd.Output()
	if err != nil {
		// Either the key opens nothing there, or the far end is an older
		// makima that does not know this username and ran it as a command.
		return nil, false
	}

	var list sshd.AccountList
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, false
	}
	return list.Accounts, len(list.Accounts) > 0
}

// probeAccounts tries the accounts worth trying on a server that cannot be
// asked: whichever one ssh would use by itself, and root.
//
// A move from Tailscale puts the person's keys in the account it logged in to,
// which on a server is often root — so root is the one other name worth a
// round trip, and the reason `makima ssh tenet` has a habit of working when
// plain `ssh tenet` does not.
func probeAccounts(ssh, host string, port int) []sshd.Account {
	var out []sshd.Account

	if sshOpens(ssh, host, port, "") {
		out = append(out, sshd.Account{Name: sshDefaultUser(ssh, host), Default: true})
	}
	if sshOpens(ssh, host, port, "root") {
		out = append(out, sshd.Account{Name: "root", Root: true})
	}

	// A default account whose name could not be read is still the account ssh
	// would use; it just cannot be named in the list.
	for i := range out {
		if out[i].Name == "" {
			out[i].Name = "root"
			out[i].Root = true
			out[i].Default = true
		}
	}
	return sshd.SortAccounts(out)
}

// sshOpens reports whether a key-only login as one account works.
func sshOpens(ssh, host string, port int, account string) bool {
	args := sshProbeArgs(port)
	if account != "" {
		args = append(args, "-l", account)
	}
	return exec.Command(ssh, append(args, host, "true")...).Run() == nil
}

// sshProbeArgs are the options every probe shares: never ask for anything,
// never wait long, and take a host key on first sight — the mesh address has
// already proved which machine it is.
func sshProbeArgs(port int) []string {
	args := []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=accept-new",
	}
	if port != 0 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	return args
}

// sshDefaultUser is the account ssh itself would use for a host, which is the
// person's own name unless their ~/.ssh/config says otherwise.
func sshDefaultUser(ssh, host string) string {
	out, err := exec.Command(ssh, "-G", host).Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if name, ok := strings.CutPrefix(line, "user "); ok {
				return strings.TrimSpace(name)
			}
		}
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
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
	// An address is already something ssh can dial, and nothing is gained by
	// checking it against the peer list — a mesh address that is not in it is
	// still the address somebody typed.
	if _, err := netip.ParseAddr(name); err == nil {
		return name, nil
	}

	c, err := localapi.Dial(localapi.SocketPath(conf.DefaultPath))
	if err != nil {
		// Not root, which is who runs ssh: the read-only socket answers this
		// just as well, and ssh must run as the person, with their keys.
		c, err = localapi.Dial(localapi.GUISocketPath(conf.DefaultPath))
	}
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
