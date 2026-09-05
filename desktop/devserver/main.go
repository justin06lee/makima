// Command devserver serves a plausible makima status on a socket, so the
// desktop app can be worked on without root and without a mesh.
//
// It exists because the alternative is worse. Building the UI against a real
// daemon means running one, which means a TUN device, which means sudo, which
// means the person changing a margin has to reconfigure their network first.
// This serves the same types the daemon does — localapi.Status, not a
// hand-written JSON blob — so a field that changes shape on the Go side breaks
// this too, and the app is never developed against a fiction.
//
//	go run ./desktop/devserver
//	MAKIMA_GUI_SOCKET=/tmp/makima-dev.sock bun run tauri dev
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/serve"
)

func main() {
	sock := flag.String("socket", "/tmp/makima-dev.sock", "where to listen")
	httpAddr := flag.String("http", "127.0.0.1:8099", "also answer over TCP here, for the interface in a plain browser; empty for none")
	flag.Parse()

	ln, err := localapi.ListenSocket(*sock)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: localapi.NewServer(&fake{started: time.Now()}, false).Handler()}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Print(err)
		}
	}()

	log.Printf("serving a pretend mesh on %s", *sock)
	log.Printf("point the app at it:  MAKIMA_GUI_SOCKET=%s bun run tauri dev", *sock)

	// The same handler over loopback TCP, so `bun run dev` in a browser can
	// show the interface with no Tauri at all — vite proxies /api here. The
	// browser cannot run the CLI, so actions are pretended on that side.
	if *httpAddr != "" {
		go func() {
			log.Printf("and on http://%s — open http://localhost:5183 after 'bun run dev'", *httpAddr)
			if err := http.ListenAndServe(*httpAddr, srv.Handler); err != nil {
				log.Print(err)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Print("done")
}

var (
	errReadOnly = errors.New("this is a development server; it shows a mesh but cannot change one")
	errNoPeer   = errors.New("no peer by that name")
)

// fake implements localapi.Backend with a mesh that looks like somebody's.
//
// The numbers are drawn from a real machine rather than invented: three
// peers, one relayed and one offline, and the sort of services auto-serve
// actually finds on a desktop that has been used for anything.
type fake struct{ started time.Time }

func (f *fake) Status() localapi.Status {
	addr := func(s string) netip.Addr { return netip.MustParseAddr(s) }

	return localapi.Status{
		Version: "dev",
		Node: localapi.NodeInfo{
			Name:      "macbook",
			Address:   addr("100.64.0.3"),
			Interface: "utun6",
		},
		Managed: true,
		Server:  "http://tenet:8080",
		Domain:  "makima",
		Relay:   localapi.RelayInfo{URL: "relay.example:3478", Connected: true},
		Peers: []localapi.PeerInfo{
			{
				Name: "tenet", Address: addr("100.64.0.1"), Online: true,
				Path: "direct 192.168.1.253:41641", Direct: true,
				Latency: 3 * time.Millisecond,
				Services: []netmap.Service{
					{Name: "ollama", Port: 11434, Scheme: "http"},
					{Name: "jupyter", Port: 8888, Scheme: "http"},
					{Name: "caddy", Port: 2019, Scheme: "http"},
					{Name: "frieren", Port: 7420},
				},
				ExitNode: true,
			},
			{
				Name: "vps", Address: addr("100.64.0.2"), Online: true,
				Path: "relay relay.example:3478", RelayURL: "relay.example:3478",
				Latency:  84 * time.Millisecond,
				Services: []netmap.Service{{Name: "grafana", Port: 3000, Scheme: "http"}},
				ExitNode: true,
			},
			{Name: "old-laptop", Address: addr("100.64.0.4"), Path: "no path"},
		},
		Services: []serve.Status{
			{
				Service:   serve.Service{Name: "vite", Port: 5183, Target: "127.0.0.1:5183", Auto: true},
				Listening: true, TargetUp: true, Active: 1, Total: 12,
			},
			{
				Service:   serve.Service{Name: "postgres", Port: 5432, Target: "127.0.0.1:5432"},
				Listening: true, TargetUp: true, Total: 3,
			},
			// Published, but nothing is answering behind it — by far the most
			// common way this is misconfigured, so the UI has to show it.
			{
				Service:   serve.Service{Name: "docs", Port: 3000, Target: "127.0.0.1:3000", Auto: true},
				Listening: true, Failed: 4,
			},
		},
		Firewall:  netcfg.Report{Backend: "none", Trusted: true},
		DNSActive: true,
		Inbox:     localapi.InboxInfo{Dir: "/Users/you/Downloads/makima", Active: true, Received: 2},
		SSH: localapi.SSHInfo{
			Active: true, Addr: "100.64.0.3:2222", User: "you", Keys: 2,
			Sources:     []string{"github:justin06lee"},
			Fingerprint: "SHA256:9pQ4t0mKZ1xRc3vLb8yNwE2hJfA6sDgU7oXiP5rTnQk",
		},
		Since: f.started,
	}
}

func (f *fake) Diagnose() localapi.Diagnosis {
	return localapi.Diagnosis{Checks: []localapi.Check{
		{Name: "Tunnel", OK: true, Detail: "utun6 is up on 100.64.0.3"},
		{Name: "Control plane", OK: true, Detail: "http://tenet:8080, last polled 2s ago"},
		{Name: "Relay", OK: true, Detail: "connected to relay.example:3478"},
		{
			Name: "Peer old-laptop", OK: false,
			Detail: "no direct path and no relay in common; it has not polled in 3 days",
			Fix:    "makima ping -until-direct old-laptop",
		},
		// A warning is OK false with Warning true — that is what makes
		// Diagnosis.OK() ignore it while the UI still shows it.
		{
			Name: "Mesh DNS", OK: false, Warning: true,
			Detail: "*.makima resolves, but this machine is also running Tailscale",
		},
	}}
}

// Everything below is refused: this socket is read-only, which is the same
// contract the daemon's desktop socket has.
func (f *fake) AddService(serve.Service) error        { return errReadOnly }
func (f *fake) RemoveService(uint16) error            { return errReadOnly }
func (f *fake) SetExitNode(string) error              { return errReadOnly }
func (f *fake) SetAdvertiseExit(bool) error           { return errReadOnly }
func (f *fake) AllowFirewall() (netcfg.Report, error) { return netcfg.Report{}, errReadOnly }
func (f *fake) SetInbox(string, bool) error           { return errReadOnly }
func (f *fake) SetSSH(bool, []string, string) error   { return errReadOnly }
func (f *fake) OpenPairing(int) (localapi.PairingState, error) {
	return localapi.PairingState{}, errReadOnly
}
func (f *fake) ClosePairing() {}

func (f *fake) Pair(context.Context, string) (localapi.PairedResult, error) {
	return localapi.PairedResult{}, errReadOnly
}

func (f *fake) Ping(name string) (localapi.Ping, error) {
	for _, p := range f.Status().Peers {
		if p.Name == name {
			return localapi.Ping{
				Name: p.Name, Address: p.Address, Direct: p.Direct, Path: p.Path,
				Latency: p.Latency, RelayURL: p.RelayURL,
			}, nil
		}
	}
	return localapi.Ping{}, errNoPeer
}
