package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/update"
)

// updateCmd asks every node to move to a release: the latest, or the one
// named. Nodes that are on move within seconds; one that is off moves when it
// next comes on. The same thing `makima update` does from any machine.
func updateCmd(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	statePath := fs.String("state", DefaultStatePath, "path to control plane state")
	socketPath := fs.String("socket", "", "admin socket path (default: beside the state file)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	admin, live := control.DialAdmin(sock(*socketPath, *statePath))
	if !live {
		return errors.New("the server is not running, so there is nobody to pass an update on to the nodes — start it first")
	}

	tag := fs.Arg(0)
	if tag == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		latest, err := update.Latest(ctx, version)
		if err != nil {
			return fmt.Errorf("find the latest release: %w", err)
		}
		tag = latest
	}

	o, err := admin.RequestUpdate(tag)
	if err != nil {
		return err
	}
	fmt.Printf("every machine that is on moves to %s now, and one that is off when it next comes on.\n", o.Tag)
	fmt.Print("a machine already on it, or on a newer build, is left alone.\n\n")
	fmt.Print("watch it with: makima-server nodes\n")
	return nil
}

// versionColumn is a node's release as `nodes` shows it: what it runs, or how
// its move to another is going.
func versionColumn(v string, u *netmap.UpdateStatus) string {
	if v == "" {
		v = "—"
	}
	if u == nil {
		return v
	}
	switch u.State {
	case netmap.UpdateFailed:
		return fmt.Sprintf("%s (%s failed: %s)", v, u.Tag, u.Error)
	default:
		return fmt.Sprintf("%s → %s, %s", v, u.Tag, u.State)
	}
}
