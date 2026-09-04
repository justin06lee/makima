package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/drop"
	"github.com/justin06lee/makima/internal/localapi"
)

// `makima cp` sends a file to another machine you own.
//
// makima could already reach every port on every one of them and still had no
// way to move a file, which is the thing people want second, right after a
// shell. Every workaround is worse than it looks: scp needs an sshd and an
// account, a web server needs somewhere to put the file first, and a chat
// client sends it to a stranger's datacentre and back.
//
// It is push-only, like scp's simplest form and like the tools it competes
// with. Pulling would mean letting a peer read a path of its choosing on this
// machine, which is a much larger promise than "you may put a file in one
// directory" — and `makima ssh desktop cat notes.txt` already covers it for
// anyone who wants it.

func cpCmd(args []string) error {
	fs := flag.NewFlagSet("cp", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	quiet := fs.Bool("q", false, "no progress output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) < 2 {
		return errors.New("cp needs a file and a destination: makima cp notes.txt desktop:")
	}

	// The destination is the last argument, which is the one convention every
	// copy tool shares.
	dest := rest[len(rest)-1]
	files := rest[:len(rest)-1]

	peerName, _, ok := drop.ParseTarget(dest)
	if !ok {
		return fmt.Errorf("%q is not a destination — it should look like 'desktop:' (%w)", dest, drop.ErrNoDestination)
	}

	// Every local file is checked before anything is sent, so a typo in the
	// third of four names does not leave two already copied.
	for _, f := range files {
		if _, _, looksRemote := drop.ParseTarget(f); looksRemote {
			return fmt.Errorf("%q looks like a second destination; cp sends to one machine at a time", f)
		}
		if _, err := os.Stat(f); err != nil {
			return err
		}
	}

	c, err := dialDaemon(*path)
	if err != nil {
		return err
	}

	st, err := c.Status()
	if err != nil {
		return err
	}
	addr, err := peerAddress(st, peerName)
	if err != nil {
		return err
	}

	from := st.Node.Name
	for _, f := range files {
		if err := sendOne(addr, f, from, *quiet); err != nil {
			return err
		}
	}
	return nil
}

// peerAddress resolves a peer name to its mesh address.
func peerAddress(st localapi.Status, name string) (netip.Addr, error) {
	bare := strings.TrimSuffix(name, "."+st.Domain)

	known := make([]string, 0, len(st.Peers))
	for _, p := range st.Peers {
		if p.Name == bare || p.Name == name {
			if !p.Online && p.Path == "no path" {
				fmt.Fprintf(os.Stderr, "note: %s has no working path right now; trying anyway\n", p.Name)
			}
			return p.Address, nil
		}
		known = append(known, p.Name)
	}

	// An address typed directly still works, so a machine that has not been
	// named yet is not a dead end.
	if a, err := netip.ParseAddr(bare); err == nil {
		return a, nil
	}

	if len(known) == 0 {
		return netip.Addr{}, fmt.Errorf("no machine named %q — this one has no peers yet", name)
	}
	return netip.Addr{}, fmt.Errorf("no machine named %q — this one can see %s", name, strings.Join(known, ", "))
}

func sendOne(addr netip.Addr, path, from string, quiet bool) error {
	name := filepath.Base(path)

	var report func(sent, total int64)
	if !quiet && isTerminal() {
		report = func(sent, total int64) {
			fmt.Fprintf(os.Stderr, "\r%s  %s", name, progressBar(sent, total))
		}
	}

	started := time.Now()
	landed, err := drop.Send(addr, path, from, report)
	if report != nil {
		// Clear the progress line before printing anything else, or the
		// result appears half-overwritten by the last repaint.
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", len(name)+32))
	}
	if err != nil {
		return err
	}

	info, statErr := os.Stat(path)
	if statErr == nil {
		fmt.Printf("%s → %s (%s in %s)\n", name, landed, humanSize(info.Size()), time.Since(started).Round(time.Millisecond))
	} else {
		fmt.Printf("%s → %s\n", name, landed)
	}
	return nil
}

// progressBar renders how far a transfer has got, in one line.
func progressBar(sent, total int64) string {
	if total <= 0 {
		return humanSize(sent)
	}
	pct := float64(sent) / float64(total)

	const width = 24
	filled := int(pct * width)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)

	return fmt.Sprintf("%s %3.0f%%  %s / %s", bar, pct*100, humanSize(sent), humanSize(total))
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for size := n / unit; size >= unit; size /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// isTerminal reports whether stderr is something a progress bar makes sense
// on. Repainting a line into a log file produces thousands of lines of noise.
func isTerminal() bool {
	info, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// inboxCmd shows or changes where files from peers land.
func inboxCmd(args []string) error {
	fs := flag.NewFlagSet("inbox", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	off := fs.Bool("off", false, "stop accepting files from peers")
	on := fs.Bool("on", false, "start accepting files again, in the default place")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := dialDaemon(*path)
	if err != nil {
		return err
	}

	rest := fs.Args()
	switch {
	case *off:
		if err := c.SetInbox("", true); err != nil {
			return err
		}
		fmt.Println("This machine no longer accepts files from peers.")
		return nil

	case *on, len(rest) > 0:
		dir := ""
		if len(rest) > 0 {
			abs, err := filepath.Abs(rest[0])
			if err != nil {
				return err
			}
			dir = abs
		}
		if err := c.SetInbox(dir, false); err != nil {
			return err
		}
	}

	st, err := c.Status()
	if err != nil {
		return err
	}
	if !st.Inbox.Active {
		fmt.Println("Not accepting files. 'makima inbox -on' switches it back on.")
		return nil
	}
	fmt.Printf("Files from peers land in %s", st.Inbox.Dir)
	if st.Inbox.Received > 0 {
		fmt.Printf(" (%d received)", st.Inbox.Received)
	}
	fmt.Println()
	fmt.Printf("Send one with: makima cp FILE %s:\n", st.Node.Name)
	return nil
}
