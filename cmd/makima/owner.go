package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/localapi"
)

// ownerCmd shows or sets the local account this machine's makima belongs to.
//
// It exists because the answer is usually worked out and occasionally
// unknowable. The daemon runs as root and learns whose machine this is from
// sudo, from polkit, or from who is logged in at the screen — none of which is
// true of a machine set up over SSH as root. What that looks like from
// outside is peculiar: makima works perfectly as root and is invisible to
// every tool running as yourself, because the read-only socket those tools
// read is opened for an account and there was no account to open it for.
//
// One line fixes it, and this is the line.
func ownerCmd(args []string) error {
	fs := flag.NewFlagSet("owner", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if name := fs.Arg(0); name != "" {
		return setOwner(*path, name)
	}
	return showOwner(*path)
}

// showOwner prints who this machine belongs to, from the daemon when it is
// running and from the config when it is not.
func showOwner(path string) error {
	name := ""
	c, err := dialDaemon(path)
	if err == nil {
		st, serr := c.Status()
		if serr != nil {
			return serr
		}
		name = st.Owner
	} else {
		// A daemon that is down, or one this account cannot reach — which is
		// the very state this command is usually being run to explain. The
		// config still says who it is for.
		f, ferr := conf.Load(path)
		if ferr != nil {
			return err
		}
		name = f.Owner
	}

	if name == "" {
		fmt.Println("Nobody owns makima on this machine, so nothing running as a person can read its status —")
		fmt.Println("not the desktop app, and not makima itself without sudo.")
		fmt.Println()
		fmt.Println("Say whose machine this is with:  sudo makima owner <user>")
		return nil
	}
	fmt.Printf("%s owns makima here. From that account the desktop app and the commands that only ask —\n", name)
	fmt.Println("ping, cp, inbox — reach makima without sudo, files from peers land in their Downloads,")
	fmt.Println("and an incoming possess session runs as them.")
	return nil
}

// setOwner hands the machine to an account.
//
// Through the daemon when there is one, so the socket is reopened at once
// rather than at the next restart — somebody running this to fix a machine
// they cannot read should be able to read it immediately. Straight to the
// config when the daemon is down, so it is already right when it comes up.
func setOwner(path, name string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("naming the owner changes who may read this machine's makima: %w", localapi.ErrNeedsRoot)
	}

	c, err := dialDaemon(path)
	if err != nil {
		if !errors.Is(err, localapi.ErrNoDaemon) {
			return err
		}
		f, ferr := conf.Load(path)
		if ferr != nil {
			return ferr
		}
		f.Owner = name
		if err := conf.Save(path, f); err != nil {
			return err
		}
		fmt.Printf("%s owns makima here, from the next start.\n", name)
		return nil
	}

	if err := c.SetOwner(name); err != nil {
		return err
	}
	fmt.Printf("%s owns makima here: the desktop app can read it, so can their own ping, cp and inbox, and\n", name)
	fmt.Println("files from peers land in their Downloads.")
	return nil
}
