package localapi

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/netcfg"
	"github.com/justin06lee/makima/internal/serve"
)

// liveBackend is a real serve.Manager behind the real API, which is the whole
// chain the daemon runs minus the tunnel itself.
type liveBackend struct {
	mu   sync.Mutex
	mgr  *serve.Manager
	addr netip.Addr
	svcs []serve.Service
}

func (b *liveBackend) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Status{
		Node:     NodeInfo{Name: "desktop", Address: b.addr},
		Services: b.mgr.Status(),
	}
}

func (b *liveBackend) Diagnose() Diagnosis { return Diagnosis{} }

func (b *liveBackend) AddService(s serve.Service) error {
	b.mu.Lock()
	b.svcs = append(b.svcs, s)
	svcs, addr := append([]serve.Service(nil), b.svcs...), b.addr
	b.mu.Unlock()

	b.mgr.Apply(addr, svcs)
	return nil
}

func (b *liveBackend) RemoveService(port uint16) error {
	b.mu.Lock()
	kept := b.svcs[:0]
	for _, s := range b.svcs {
		if s.Port != port {
			kept = append(kept, s)
		}
	}
	b.svcs = kept
	svcs, addr := append([]serve.Service(nil), b.svcs...), b.addr
	b.mu.Unlock()

	b.mgr.Apply(addr, svcs)
	return nil
}

func (b *liveBackend) SetExitNode(string) error              { return nil }
func (b *liveBackend) AllowFirewall() (netcfg.Report, error) { return netcfg.Report{}, nil }

// The end-to-end shape of the fix: a service bound to localhost, published by
// the daemon on its mesh address, reachable through that address by anything
// on the mesh — with nothing rebound, no port opened, and no router involved.
func TestPublishAndReachThroughTheAPI(t *testing.T) {
	// A service that will only ever answer on loopback, exactly like Ollama.
	svcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svcLn.Close()

	go func() {
		for {
			c, err := svcLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("ollama is running"))
			}(c)
		}
	}()
	localPort := uint16(svcLn.Addr().(*net.TCPAddr).Port)

	// The daemon side.
	quiet := log.New(io.Discard, "", 0)
	backend := &liveBackend{
		mgr:  serve.New(quiet),
		addr: netip.MustParseAddr("127.0.0.1"),
	}
	defer backend.mgr.Close()

	sock := shortSocket(t)
	ln, err := ListenSocket(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: NewServer(backend, true).Handler()}
	go srv.Serve(ln)
	defer srv.Close()

	// The CLI side.
	client, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}

	meshPort := freePort(t)
	spec := strconv.Itoa(int(meshPort)) + ":" + strconv.Itoa(int(localPort))
	if err := client.Serve(spec, "ollama"); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// What a peer would do.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(meshPort)))
	conn, err := dialRetry(addr)
	if err != nil {
		t.Fatalf("the published port never answered: %v", err)
	}
	defer conn.Close()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ollama is running" {
		t.Errorf("got %q through the published port, want the service's reply", got)
	}

	// And it shows up as published and healthy.
	st, err := client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Services) != 1 {
		t.Fatalf("%d services in status, want 1", len(st.Services))
	}
	s := st.Services[0]
	if !s.Listening || !s.TargetUp || s.Name != "ollama" {
		t.Errorf("status is %+v, want a listening service named ollama with a live target", s)
	}
	if s.Total == 0 {
		t.Error("the connection that just succeeded was not counted")
	}

	// Withdrawing it stops the listener.
	if err := client.Unserve(meshPort); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		c.Close()
		t.Error("the port still answers after being withdrawn")
	}
}

func TestDialWithoutADaemon(t *testing.T) {
	_, err := Dial(filepath.Join(t.TempDir(), "nothing.sock"))
	if err == nil {
		t.Fatal("dialling a socket that does not exist succeeded")
	}
	if !isNoDaemon(err) {
		t.Errorf("got %v, want it to identify itself as no-daemon", err)
	}
}

func isNoDaemon(err error) bool {
	for err != nil {
		if err == ErrNoDaemon {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// A second daemon must refuse rather than steal the socket from the first.
func TestSocketIsNotStolenFromALiveDaemon(t *testing.T) {
	sock := shortSocket(t)

	first, err := ListenSocket(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	srv := &http.Server{Handler: NewServer(&liveBackend{mgr: serve.New(log.New(io.Discard, "", 0))}, true).Handler()}
	go srv.Serve(first)
	defer srv.Close()

	if _, err := ListenSocket(sock); err == nil {
		t.Error("a second listener took the socket from a running daemon")
	}
}

// shortSocket returns a socket path inside the OS limit.
//
// t.TempDir() on macOS is already most of the 104 bytes a Unix socket path may
// be, which is exactly the failure CheckSocketPath exists to explain — but a
// test that trips over it is testing the wrong thing.
func shortSocket(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "mak")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "d.sock")
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func dialRetry(addr string) (net.Conn, error) {
	var lastErr error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			return c, nil
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	return nil, lastErr
}
