package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/justin06lee/makima/internal/bypass"
	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/tor"
)

// Reaching the network's server from a command, not the daemon: joining from
// somewhere other than home, or leaving from there. The daemon has a tor of
// its own for this; a command starts one only if it actually has to dial an
// onion address, and stops it when it is done.

// nodeTorDir is where the daemon's tor keeps its state, beside the node's
// configuration. A command that joins uses it too — the daemon is not running
// yet — so the daemon starts with tor's state already warm.
func nodeTorDir(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "tor")
}

// onionBinder dials the way the daemon does, an onion address included. The
// returned function stops the tor, if one was started.
func onionBinder(dir string) (*bypass.Binder, func()) {
	d := &tor.Dialer{DataDir: dir, Logger: log.New(os.Stderr, "  ", 0)}
	var once sync.Once
	b := &bypass.Binder{}
	b.SetOnion(func(ctx context.Context, network, address string) (net.Conn, error) {
		once.Do(func() {
			fmt.Println("Reaching the network through tor — this takes a moment the first time.")
		})
		return d.DialContext(ctx, network, address)
	})
	return b, d.Close
}

// inviteURLs are the addresses an invite says the server answers at: the one
// it names, then its onion address.
func inviteURLs(s string, onion string) []string {
	urls := []string{strings.TrimRight(s, "/")}
	if onion != "" {
		urls = append(urls, control.OnionURL(onion))
	}
	return urls
}

// fetchKeyVerified fetches the server's key, for an invite that came as
// words, from the first of its addresses that answers as the server.
//
// A wrong key at one address is no reason to give up on the next: away from
// home, the LAN address can be somebody else's machine entirely.
func fetchKeyVerified(ctx context.Context, b *bypass.Binder, urls []string, handle string, macKey []byte) (key.Public, error) {
	var errs []error
	for _, u := range urls {
		k, err := control.FetchServerKeyVerified(ctx, b, u, handle, macKey)
		if err == nil {
			return k, nil
		}
		if ctx.Err() != nil {
			return key.Public{}, err
		}
		errs = append(errs, err)
	}
	return key.Public{}, errors.Join(errs...)
}

// serverOnion is the onion address the network's server is published at, or
// "" when it is not published.
func serverOnion(admin *control.AdminClient) string {
	urls, err := admin.ControlURLs()
	if err != nil {
		return ""
	}
	for _, raw := range urls {
		if u, err := url.Parse(raw); err == nil && tor.IsOnion(u.Hostname()) {
			return u.Hostname()
		}
	}
	return ""
}

// hostOfURL is a URL's host, or "" for one that does not parse.
func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
