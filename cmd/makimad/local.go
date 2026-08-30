package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/justin06lee/makima/internal/localapi"
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
		if uiSrv != nil {
			_ = uiSrv.Shutdown(shutdownCtx)
		}
	}, nil
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
