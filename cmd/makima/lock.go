package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/localapi"
)

// lockCmd shows this machine's copy of the network lock, or forgets it.
//
// The copy is the machine's own on purpose: the lock defends against the
// control plane, so the control plane can offer a newer version signed by a
// key already trusted here and nothing else. Forgetting it is therefore a
// thing only root on this machine can do, and the one way out of a lock whose
// every signing key is lost.
func lockCmd(args []string) error {
	fs := flag.NewFlagSet("lock", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	switch fs.Arg(0) {
	case "", "status":
		c, err := dialDaemon(*path)
		if err != nil {
			return err
		}
		st, err := c.Status()
		if err != nil {
			return err
		}
		switch {
		case st.Lock == nil:
			fmt.Println("This machine has never been shown a network lock, so it takes the network's word for who belongs to it.")
		case st.Lock.Enforced:
			fmt.Printf("Network lock version %d: enforced. Peers need a signature from one of %d trusted key(s).\n", st.Lock.Version, st.Lock.Keys)
		default:
			fmt.Printf("Network lock version %d: not enforced (%d trusted key(s)).\n", st.Lock.Version, st.Lock.Keys)
		}
		return nil

	case "reset":
		if os.Geteuid() != 0 {
			return fmt.Errorf("forgetting the network lock changes who this machine will talk to: %w", localapi.ErrNeedsRoot)
		}
		c, err := dialDaemon(*path)
		if err != nil {
			return err
		}
		if err := c.ResetLock(); err != nil {
			return err
		}
		fmt.Println("This machine has forgotten the network lock. It takes whatever lock the network shows it next as new —")
		fmt.Println("which is right after 'makima-server lock forget', and wrong at any other time.")
		return nil
	}
	return errors.New("usage: makima lock [status | reset]")
}
