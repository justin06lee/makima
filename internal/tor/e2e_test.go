package tor

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRealTor runs a real tor: publishes an onion service under a key makima
// made, and reaches it through tor — exactly the journey a node away from
// home makes to its control plane. It needs tor installed and the tor
// network, so it only runs when asked: MAKIMA_TOR_E2E=1 go test ./internal/tor
func TestRealTor(t *testing.T) {
	if os.Getenv("MAKIMA_TOR_E2E") == "" {
		t.Skip("set MAKIMA_TOR_E2E=1 to run against a real tor")
	}
	if _, err := Find(); err != nil {
		t.Skip(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s", r.Host)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "", log.Ltime)
	tr, err := Start(t.TempDir(), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	start := time.Now()
	if err := tr.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("tor joined the network in %s", time.Since(start).Round(time.Millisecond))

	host, err := tr.Publish(k, 80, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("published %s", host)

	// The fixed key the unit tests pin an address for: tor itself agrees on
	// it, or Publish would have refused.
	if got, err := tr.Publish(fixedKey(), 80, ln.Addr().String()); err != nil || got != fixedHost {
		t.Fatalf("fixed key published as %q (%v), want %s", got, err, fixedHost)
	}

	// A second tor, as another machine would be, reaches it through a Dialer.
	d := &Dialer{DataDir: t.TempDir(), Logger: logger}
	defer d.Close()

	start = time.Now()
	var conn net.Conn
	for {
		attempt, stop := context.WithTimeout(ctx, time.Minute)
		conn, err = d.DialContext(attempt, "tcp", host+":80")
		stop()
		if err == nil {
			break
		}
		t.Logf("not yet: %v", err)
		if ctx.Err() != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Second)
	}
	defer conn.Close()
	t.Logf("reached it in %s", time.Since(start).Round(time.Millisecond))

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body strings.Builder
	_, _ = bufio.NewReader(resp.Body).WriteTo(&body)
	if want := "hello from " + host; body.String() != want {
		t.Fatalf("got %q, want %q", body.String(), want)
	}
	if st := d.Status(); !st.Running || st.Progress != 100 {
		t.Errorf("dialer status %+v, want running at 100%%", st)
	}
}
