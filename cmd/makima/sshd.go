package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/sshd"
)

// `makima sshd` switches on a shell server that only the mesh can reach.
//
// `makima ssh` has always found the address and handed off to the system
// client, which works right up until the far end has no sshd — on a laptop,
// the normal case. macOS ships Remote Login off; most desktop Linux installs
// run no server; and turning one on means opening a service to every network
// that machine is ever on.
//
// This is the narrow version. It binds the mesh address and nothing else,
// there is no password authentication and no way to add one, and every session
// runs as one local account chosen here rather than by whoever connects.
//
// Off unless asked for, unlike everything else makima switches on by default.
// Publishing a port or accepting a file into one directory are bounded; a
// shell is not, and nobody should discover months later that they had one.

func sshdCmd(args []string) error {
	fs := flag.NewFlagSet("sshd", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	on := fs.Bool("on", false, "start accepting ssh from the mesh")
	off := fs.Bool("off", false, "stop")
	keys := fs.String("keys", "", "where authorized keys come from: a file path, or github:USER (comma-separated)")
	asUser := fs.String("user", "", "the local account sessions run as (default: whoever started makima)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := dialDaemon(*path)
	if err != nil {
		return err
	}

	switch {
	case *off:
		if err := c.SetSSH(false, nil, ""); err != nil {
			return err
		}
		fmt.Println("The ssh server is off.")
		return nil

	case *on, *keys != "", *asUser != "":
		var sources []string
		if *keys != "" {
			for _, s := range strings.Split(*keys, ",") {
				if s = strings.TrimSpace(s); s != "" {
					sources = append(sources, s)
				}
			}
		}
		if err := c.SetSSH(true, sources, *asUser); err != nil {
			return err
		}
	}

	st, err := c.Status()
	if err != nil {
		return err
	}
	fmt.Print(sshStatusReport(st))
	return nil
}

// sshStatusReport renders the server's state, or how to switch it on.
func sshStatusReport(st localapi.Status) string {
	var b strings.Builder
	s := st.SSH

	if !s.Active {
		b.WriteString("The ssh server is off.\n\n")
		b.WriteString("  makima sshd -on                    use ~/.ssh/authorized_keys\n")
		b.WriteString("  makima sshd -on -keys github:you   use the keys on your GitHub account\n")
		if s.KeyError != "" {
			fmt.Fprintf(&b, "\nlast attempt: %s\n", s.KeyError)
		}
		return b.String()
	}

	fmt.Fprintf(&b, "Accepting ssh on %s as %s.\n", s.Addr, s.User)
	fmt.Fprintf(&b, "%d authorized key(s)", s.Keys)
	if len(s.Sources) > 0 {
		fmt.Fprintf(&b, " from %s", strings.Join(s.Sources, ", "))
	}
	b.WriteString("\n")
	// Printed so it can be checked out of band rather than trusted on first
	// use, which is the only way a host key check means anything.
	fmt.Fprintf(&b, "host key %s\n", s.Fingerprint)
	if s.KeyError != "" {
		fmt.Fprintf(&b, "note: %s\n", s.KeyError)
	}
	fmt.Fprintf(&b, "\nFrom another machine:  makima ssh %s\n", st.Node.Name)
	fmt.Fprintf(&b, "Port %d, and only on the mesh address.\n", sshd.DefaultPort)
	return b.String()
}
