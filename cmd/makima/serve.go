package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/serve"
)

// These all talk to the running daemon, because the running daemon is where
// the answers are. A config file can say which ports should be published; only
// the daemon knows whether they are, whether anything is listening behind
// them, and whether the host firewall is quietly eating the traffic.

// dialDaemon connects to the local daemon, with an error worth reading when
// there is not one.
func dialDaemon(configPath string) (*localapi.Client, error) {
	c, err := localapi.Dial(localapi.SocketPath(configPath))
	if err == nil {
		return c, nil
	}

	// Not root, most likely. The daemon keeps a second, read-only socket for
	// the person who started it, and everything that only asks — status,
	// ping, cp — works over that one just as well. Anything that changes
	// something is refused there with a message that says to use sudo: the
	// right answer, arriving after the question was actually asked rather
	// than before.
	if os.Geteuid() != 0 {
		if g, gerr := localapi.Dial(localapi.GUISocketPath(configPath)); gerr == nil {
			return g, nil
		}
		// The root socket is there but out of reach: the daemon is running,
		// and this account is not the one that started it.
		if _, serr := os.Stat(localapi.SocketPath(configPath)); serr == nil {
			return nil, errors.New("makima is running, but this account cannot reach it — run it again with sudo")
		}
	}

	if errors.Is(err, localapi.ErrNoDaemon) {
		return nil, fmt.Errorf("%w — start it with: makima up", err)
	}
	return nil, err
}

func serveCmd(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "list", "ls":
			return serveList(args[1:])
		case "rm", "remove", "stop":
			return serveRemove(args[1:])
		}
	}
	return serveAdd(args)
}

func serveAdd(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	name := fs.String("name", "", "a label for this service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("serve needs a port, e.g. 'makima serve 11434'")
	}

	spec := fs.Arg(0)
	// Parsed here as well as in the daemon, so a typo is rejected before a
	// round trip and the error names the thing that was typed.
	if _, err := serve.ParseSpec(spec); err != nil {
		return err
	}

	// Publishing changes the tunnel, which only root may do. Asked for here,
	// before anything else, rather than discovered as a refusal afterwards.
	if err := mustBeRoot(); err != nil {
		return err
	}

	c, err := dialDaemon(*path)
	if err != nil {
		return err
	}
	if err := c.Serve(spec, *name); err != nil {
		return err
	}

	st, err := c.Status()
	if err != nil {
		return err
	}

	svc, _ := serve.ParseSpec(spec)
	fmt.Printf("published %s\n\n", svc)
	if st.Node.Address.IsValid() {
		host := st.Node.Address.String()
		if st.Domain != "" {
			host = fmt.Sprintf("%s.%s", dnsName(st.Node.Name), st.Domain)
		}
		fmt.Printf("reachable from every machine on the mesh at:\n  %s:%d\n\n", host, svc.Port)
	}

	// The two things that most often make a freshly published port look
	// broken, checked immediately rather than left to be discovered.
	for _, s := range st.Services {
		if s.Port != svc.Port {
			continue
		}
		if s.Error != "" {
			fmt.Printf("but it is not listening: %s\n", s.Error)
		} else if !s.TargetUp {
			fmt.Printf("note: nothing is listening on %s right now.\n", s.Target)
			fmt.Print("      peers will connect and get nothing until the service starts.\n")
		}
	}
	if !st.Firewall.OK() {
		fmt.Printf("\nwarning: %s\n", st.Firewall.Detail)
		fmt.Print("run 'makima firewall allow' or peers will not get through.\n")
	}
	return nil
}

func serveRemove(args []string) error {
	fs := flag.NewFlagSet("serve rm", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("serve rm needs a port")
	}

	port, err := strconv.ParseUint(fs.Arg(0), 10, 16)
	if err != nil {
		return fmt.Errorf("%q is not a port", fs.Arg(0))
	}
	if err := mustBeRoot(); err != nil {
		return err
	}

	c, err := dialDaemon(*path)
	if err != nil {
		return err
	}
	if err := c.Unserve(uint16(port)); err != nil {
		return err
	}
	fmt.Printf("withdrew port %d\n", port)
	return nil
}

func serveList(args []string) error {
	fs := flag.NewFlagSet("serve list", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
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

	if len(st.Services) == 0 {
		fmt.Print("nothing published from this machine\n\n")
		fmt.Print("publish a local port with:\n  makima allow 11434\n")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprint(w, "MESH PORT\tFORWARDS TO\tNAME\tSTATE\n")
	for _, s := range st.Services {
		state := "ready"
		switch {
		case s.Error != "":
			state = "FAILED: " + s.Error
		case !s.Listening:
			state = "not listening"
		case !s.TargetUp:
			state = "nothing on " + s.Target
		case s.Active > 0:
			state = fmt.Sprintf("ready, %d open", s.Active)
		}
		fmt.Fprintf(w, ":%d\t%s\t%s\t%s\n", s.Port, s.Target, orDash(s.Name), state)
	}
	return w.Flush()
}

// --- doctor ---------------------------------------------------------------

func doctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := dialDaemon(*path)
	if err != nil {
		return err
	}
	d, err := c.Diagnose()
	if err != nil {
		return err
	}

	for _, chk := range d.Checks {
		mark := "✓"
		if !chk.OK {
			mark = "✗"
			if chk.Warning {
				mark = "!"
			}
		}
		fmt.Printf("%s %s\n", mark, chk.Name)
		fmt.Printf("   %s\n", chk.Detail)
		if chk.Fix != "" && !chk.OK {
			fmt.Printf("   fix: %s\n", chk.Fix)
		}
		fmt.Println()
	}

	if d.OK() {
		fmt.Print("everything checks out.\n")
		return nil
	}
	// A non-zero exit so this is usable from a script, and so a shell prompt
	// that shows exit status says something happened.
	return errors.New("some checks failed; see above")
}

// --- firewall -------------------------------------------------------------

func firewallCmd(args []string) error {
	if len(args) == 0 {
		return firewallStatusCmd(nil)
	}
	switch args[0] {
	case "status":
		return firewallStatusCmd(args[1:])
	case "allow":
		return firewallAllowCmd(args[1:])
	default:
		return fmt.Errorf("unknown firewall subcommand %q (try: status, allow)", args[0])
	}
}

func firewallStatusCmd(args []string) error {
	fs := flag.NewFlagSet("firewall status", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
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
	printFirewall(st.Firewall)
	return nil
}

func firewallAllowCmd(args []string) error {
	fs := flag.NewFlagSet("firewall allow", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := mustBeRoot(); err != nil {
		return err
	}

	c, err := dialDaemon(*path)
	if err != nil {
		return err
	}
	r, err := c.AllowFirewall()
	if err != nil {
		return err
	}
	printFirewall(r)
	return nil
}

func printFirewall(r netcfg.Report) {
	fmt.Printf("backend   %s\n", r.Backend)
	fmt.Printf("filtering %s\n", yesNo(r.Active))
	if r.Active {
		fmt.Printf("tunnel    %s\n", map[bool]string{true: "trusted", false: "NOT TRUSTED"}[r.Trusted])
	}
	fmt.Printf("\n%s\n", r.Detail)
	if !r.OK() && r.Manual != "" {
		fmt.Printf("\nto fix it by hand:\n  %s\n", r.Manual)
	}
}

// --- ui -------------------------------------------------------------------

func uiCmd(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	addr := fs.String("addr", "127.0.0.1:8088", "address the daemon is serving the UI on")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Confirm the daemon is up before opening a browser at nothing.
	if _, err := dialDaemon(*path); err != nil {
		return err
	}

	url := "http://" + *addr + "/"
	if !reachable(*addr) {
		return fmt.Errorf(
			"nothing is serving the web page on %s. The desktop app is the usual interface;\nfor the web page too, start makima with it on:\n  sudo makimad -ui %s -ui-write",
			*addr, *addr)
	}

	fmt.Printf("opening %s\n", url)
	return openBrowser(url)
}

func reachable(addr string) bool {
	c, err := netDialTimeout(addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}

	if _, err := exec.LookPath(cmd); err != nil {
		// A headless server is the normal case for the machine this is most
		// useful on, so this is information rather than a failure.
		fmt.Printf("no browser opener here; visit it yourself:\n  %s\n", url)
		return nil
	}
	return exec.Command(cmd, append(args, url)...).Start()
}

// --- helpers --------------------------------------------------------------

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// dnsName mirrors the resolver's name normalisation so the address printed
// after publishing a port is the one that actually resolves.
func dnsName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == ' ', r == '.', r == '_':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
