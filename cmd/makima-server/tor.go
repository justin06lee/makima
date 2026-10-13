package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/tor"
)

// Reaching this network from anywhere: an onion service for the server's own
// port, published by a tor this server runs. Nodes use the address they
// joined through while it answers, and the onion address when it does not —
// the laptop has left the house — with nothing forwarded on any router and
// nothing to keep pointed at a home connection whose address changes.

// onionKeyPath is where the onion service's key lives: beside the state, like
// the relay's, and for the same reason — nodes are told the address once.
func onionKeyPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "control-onion.json")
}

// torDataDir is where the server's tor keeps its state between runs.
func torDataDir(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "tor")
}

// startOnion publishes the server as an onion service until ctx ends, and
// returns the listener tor forwards to — which the caller serves the control
// plane on — or nil when there is nothing to publish.
//
// Tor's connections arrive on a listener of their own rather than the public
// port: they all come from loopback, and loopback is believed about whom it
// forwards for. On this listener nothing is believed — a client over tor
// could otherwise name any address it liked and spend that address's budget.
func startOnion(ctx context.Context, store *control.Store, statePath string, handler http.Handler) (net.Listener, http.Handler, error) {
	if _, err := tor.Find(); err != nil {
		// Nodes told about an address nobody publishes would only spend time
		// knocking there.
		if err := store.ClearOnion(); err != nil {
			return nil, nil, err
		}
		store.NoteTor(tor.ServiceState{Phase: tor.PhaseNotInstalled, Detail: err.Error(), Since: time.Now()})
		log.Printf("tor      not installed, so this network is reachable only where this machine is: %v", err)
		return nil, nil, nil
	}

	k, err := tor.LoadKey(onionKeyPath(statePath))
	if err != nil {
		return nil, nil, fmt.Errorf("onion service: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("onion service: %w", err)
	}
	if err := store.SetOnion(k.Host()); err != nil {
		ln.Close()
		return nil, nil, err
	}

	svc := &tor.Service{
		DataDir:  torDataDir(statePath),
		Key:      k,
		VirtPort: 80,
		Target:   ln.Addr().String(),
		Logger:   log.Default(),
		OnState:  store.NoteTor,
	}
	go svc.Run(ctx)

	log.Printf("onion    %s (publishing through tor)", k.Host())
	return ln, stripForwarded(handler), nil
}

// stripForwarded drops what a client says about whom it is, for connections
// that came through tor: tor adds no such header, so any there is the
// client's own invention.
func stripForwarded(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("Forwarded")
		h.ServeHTTP(w, r)
	})
}

// torCmd is `makima-server tor`: whether this network can be reached from
// anywhere, and at what address.
func torCmd(args []string) error {
	af := newAdminFlags("tor")
	t, err := af.open(args)
	if err != nil {
		return err
	}

	var (
		onion string
		st    tor.ServiceState
	)
	if t.live() {
		if st, err = t.admin.Tor(); err != nil {
			return err
		}
		urls, err := t.admin.ControlURLs()
		if err != nil {
			return err
		}
		for _, u := range urls {
			if tor.IsOnion(hostOfURL(u)) {
				onion = u
			}
		}
	} else {
		onion = t.store.Onion()
	}

	if onion != "" {
		fmt.Printf("%-10s %s\n", "address", onion)
	}
	if !t.live() {
		if onion == "" {
			fmt.Println("no onion address yet: the server publishes one when it starts, if tor is installed.")
			return nil
		}
		fmt.Printf("%-10s published while the server runs; it is not running now\n", "status")
		return nil
	}
	fmt.Printf("%-10s %s\n", "status", describeTor(st))
	return nil
}

// describeTor words a publishing state for a person.
func describeTor(st tor.ServiceState) string {
	since := ""
	if !st.Since.IsZero() {
		since = fmt.Sprintf(" (for %s)", time.Since(st.Since).Round(time.Second))
	}
	switch st.Phase {
	case tor.PhaseReachable:
		return "reachable from anywhere, through tor" + since
	case tor.PhasePublishing:
		return "published; checking it can be reached" + since
	case tor.PhaseConnecting:
		return fmt.Sprintf("connecting to the tor network, %d%%: %s", st.Progress, st.Detail)
	case tor.PhaseStarting:
		return "starting tor"
	case tor.PhaseNotInstalled:
		return "tor is not installed on this machine — install it (brew install tor, or apt install tor) and the server publishes within five minutes"
	case tor.PhaseFailed:
		return "FAILING: " + st.Detail + " — trying again"
	case tor.PhaseOff:
		return "off: the server was started with -no-tor, so it is reachable only where this machine is"
	}
	return "not started yet"
}

// hostOfURL is a URL's host, or "" for one that does not parse.
func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
