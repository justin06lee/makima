package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netcfg"
)

// logf is the daemon's logger, wrapped so code that is not in main.go does not
// have to reach for the standard logger directly.
func logf(format string, args ...any) { log.Printf(format, args...) }

// openFirewall makes the host firewall accept traffic arriving on the tunnel.
//
// Done automatically, and that is a deliberate choice rather than an
// oversight. A host firewall silently dropping tunnel traffic is the single
// most common reason a working mesh looks broken, it produces no error
// anywhere, and the symptom — connection times out — is indistinguishable
// from a routing problem. Leaving it to the operator means leaving them to
// debug it.
//
// What is installed is narrow and reversible: accept input on this interface,
// removed again on shutdown. No port is opened to the LAN or the internet, and
// -no-firewall turns the whole thing off for anyone who would rather manage it
// themselves.
func (n *node) openFirewall() {
	before := n.firewall.Status()
	if before.OK() {
		if before.Active {
			logf("host firewall: %s already allows %s", before.Backend, n.engine.Name())
		}
		return
	}

	if !before.Automatic {
		logf("WARNING: %s", before.Detail)
		logf("mesh traffic will be dropped until you run:")
		logf("  %s", before.Manual)
		return
	}

	after, err := n.firewall.Allow()
	if err != nil {
		logf("WARNING: could not configure %s: %v", before.Backend, err)
		logf("mesh traffic will be dropped until you run:")
		logf("  %s", before.Manual)
		return
	}
	if !after.OK() {
		logf("WARNING: %s still appears to be dropping tunnel traffic", after.Backend)
		return
	}
	logf("host firewall: told %s to trust %s (undone on exit)", after.Backend, n.engine.Name())
}

// openListenPort lets WireGuard's own packets in, on the port it listens on.
//
// Trusting the tunnel interface is not enough on its own: the encrypted
// packets arrive on the LAN interface first, and a firewall that drops them
// there leaves a tunnel that registers, gets its peers, and never completes a
// handshake with any of them. Kept after exit — it is what lets this machine
// be reached at all, and the next start would only open it again.
func (n *node) openListenPort(port int) {
	if port <= 0 {
		return
	}
	via, err := netcfg.OpenPort("udp", port)
	switch {
	case err != nil:
		logf("WARNING: could not open UDP %d in the host firewall: %v", port, err)
		logf("peers may not be able to reach this machine directly until it is open")
	case via != "":
		logf("host firewall: %s lets UDP %d in, for WireGuard", via, port)
	}
}

// serveLocalAPI starts the daemon's local socket and, if asked, the web UI.
//
// Two listeners with different powers. The socket is owner-only and may change
// things, which is safe because reaching it already requires being able to
// write this node's private keys. A TCP listener may not, unless -ui-write
// says so: a browser tab is a much wider door than a Unix socket, and the
// difference between "show me" and "reconfigure my VPN" should not depend on
// nobody having found the port.
func (n *node) serveLocalAPI(ctx context.Context, opts options) (func(), error) {
	sockPath := localapi.SocketPath(opts.configPath)

	ln, err := localapi.ListenSocket(sockPath)
	if err != nil {
		return nil, err
	}

	sockSrv := &http.Server{Handler: localapi.NewServer(n, true).Handler()}
	go func() {
		if err := sockSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("local socket: %v", err)
		}
	}()
	logf("local socket %s", sockPath)

	// A second socket for a desktop app: read-only, and owned by the person
	// this machine belongs to rather than by root.
	n.openGUISocket(opts.configPath)

	var uiSrv *http.Server
	if opts.uiAddr != "" {
		uiLn, err := net.Listen("tcp", opts.uiAddr)
		if err != nil {
			sockSrv.Close()
			ln.Close()
			return nil, err
		}

		uiSrv = &http.Server{
			Handler:           localapi.NewServer(n, opts.uiWrite).Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := uiSrv.Serve(uiLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logf("web ui: %v", err)
			}
		}()

		logf("web ui   http://%s/%s", opts.uiAddr, map[bool]string{true: "", false: "  (read-only)"}[opts.uiWrite])
		if opts.uiWrite && !loopbackOnly(opts.uiAddr) {
			// Worth saying plainly. Anything that can reach this address can
			// republish this node's ports and change where its traffic goes.
			logf("WARNING: the web UI is writable and not bound to loopback; anyone who can reach %s controls this node", opts.uiAddr)
		}
	}

	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = sockSrv.Shutdown(shutdownCtx)
		n.closeGUISocket()
		if uiSrv != nil {
			_ = uiSrv.Shutdown(shutdownCtx)
		}
	}, nil
}

// openGUISocket opens the read-only socket a desktop app — and anything else
// running as a person rather than as root — reads status from.
//
// Idempotent, and called again when the owner changes: whoever the machine
// belongs to now is who the socket is for, and reopening it is what makes
// `makima owner` take effect without a restart.
//
// Failures here are reported and shrugged off. A machine with no desktop app
// on it is the common case, and a daemon that refused to bring up a tunnel
// because it could not create a socket for a GUI would have its priorities
// backwards.
func (n *node) openGUISocket(configPath string) {
	owner := n.owner()

	n.guiMu.Lock()
	defer n.guiMu.Unlock()
	n.shutGUILocked()

	if owner == nil {
		return
	}

	path := localapi.GUISocketPath(configPath)
	ln, err := localapi.ListenUserSocket(path, owner.UID, owner.GID)
	if err != nil {
		logf("desktop socket: %v", err)
		return
	}

	// allowWrite false: this socket can be read and nothing else. Everything
	// the app can change, it changes by running the CLI.
	srv := &http.Server{Handler: localapi.NewServer(n, false).Handler()}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("desktop socket: %v", err)
		}
	}()
	n.guiSrv, n.guiLn = srv, ln
	logf("desktop socket %s, readable by %s", path, owner.Name)
}

// closeGUISocket shuts the desktop socket down for good, on the way out.
func (n *node) closeGUISocket() {
	n.guiMu.Lock()
	defer n.guiMu.Unlock()
	n.shutGUILocked()
}

// shutGUILocked closes whatever is currently serving the desktop socket, with
// n.guiMu held.
func (n *node) shutGUILocked() {
	if n.guiSrv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = n.guiSrv.Shutdown(ctx)
	_ = n.guiLn.Close()
	n.guiSrv, n.guiLn = nil, nil
}

// loopbackOnly reports whether an address can only be reached from this
// machine.
func loopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		// A bare ":8088" binds every interface, which is the case worth
		// warning about most.
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
