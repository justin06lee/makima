package tor

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSocks accepts one SOCKS5 CONNECT, records the name asked for, and
// answers with code — then, on success, echoes.
func fakeSocks(t *testing.T, code byte) (addr string, asked chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	asked = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hello := make([]byte, 3)
		if _, err := io.ReadFull(conn, hello); err != nil {
			return
		}
		conn.Write([]byte{5, 0})
		head := make([]byte, 5)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		rest := make([]byte, int(head[4])+2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return
		}
		port := int(rest[len(rest)-2])<<8 | int(rest[len(rest)-1])
		asked <- string(rest[:len(rest)-2]) + ":" + strconv.Itoa(port)
		conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		if code == 0 {
			io.Copy(conn, conn)
		}
	}()
	return ln.Addr().String(), asked
}

func TestSocksSendsTheNameNotAnAddress(t *testing.T) {
	proxy, asked := fakeSocks(t, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := socksDial(ctx, proxy, fixedHost+":80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := <-asked; got != fixedHost+":80" {
		t.Errorf("asked tor for %q", got)
	}
	// The connection is the stream now: what goes in comes back.
	conn.Write([]byte("ping"))
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "ping" {
		t.Errorf("echo: %q, %v", b, err)
	}
}

func TestSocksSaysTheServiceIsNotPublished(t *testing.T) {
	proxy, _ := fakeSocks(t, 0xF0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := socksDial(ctx, proxy, fixedHost+":80")
	var de *DialError
	if !errors.As(err, &de) || !de.Unpublished() {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "not published") {
		t.Errorf("message %q does not say why", err)
	}
}

func TestSocksGivesUpWithTheContext(t *testing.T) {
	// A SOCKS port that accepts and then says nothing — tor building a
	// circuit that never completes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(5 * time.Second)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := socksDial(ctx, ln.Addr().String(), fixedHost+":80"); err == nil {
		t.Fatal("dial succeeded against a silent proxy")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %s to give up", d)
	}
}

func TestDialerRefusesWhatIsNotOnion(t *testing.T) {
	d := &Dialer{DataDir: t.TempDir()}
	if _, err := d.DialContext(context.Background(), "tcp", "192.168.1.253:8081"); !errors.Is(err, errNotOnion) {
		t.Fatalf("got %v", err)
	}
}
