package relay

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A session that got going resets the wait; only failures grow it.
func TestBackoffStartsAgainAfterASessionThatWorked(t *testing.T) {
	b := time.Second
	for range 10 {
		b = nextBackoff(b, false)
	}
	if b > 32*time.Second {
		t.Errorf("backoff grew to %s; it is capped", b)
	}
	if got := nextBackoff(b, true); got != time.Second {
		t.Errorf("after a session that worked the wait is %s, want 1s", got)
	}
}

// muteProxy stands between a client and a relay and, once muted, stops
// passing anything from the relay back — a path that went quiet without
// either end being told, which is what a NAT dropping the mapping looks like.
func muteProxy(t *testing.T, relayAddr string) (string, *atomic.Bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var muted atomic.Bool
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", relayAddr)
			if err != nil {
				in.Close()
				continue
			}
			go io.Copy(out, in)
			go func() {
				buf := make([]byte, 64<<10)
				for {
					n, err := out.Read(buf)
					if err != nil {
						return
					}
					if muted.Load() {
						continue
					}
					if _, err := in.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), &muted
}

// The keepalive used to be the whole of liveness, and it cannot see this:
// its pings are written into the kernel's buffer and succeed. The client
// has to notice it has heard nothing.
func TestClientNoticesARelayThatWentQuiet(t *testing.T) {
	was := readTimeout
	readTimeout = 300 * time.Millisecond
	t.Cleanup(func() { readTimeout = was })

	_, addr, relayKey := testRelay(t)
	proxy, muted := muteProxy(t, addr)
	c, _ := connect(t, proxy, relayKey)

	muted.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	for c.Connected() {
		if time.Now().After(deadline) {
			t.Fatal("the client still believes it is connected to a relay it has not heard from")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The relay drops a client it has not heard from, rather than queueing
// packets into a dead socket until TCP gives up.
func TestRelayDropsAClientThatWentQuiet(t *testing.T) {
	was := clientSilence
	clientSilence = 300 * time.Millisecond
	t.Cleanup(func() { clientSilence = was })

	srv, addr, relayKey := testRelay(t)
	connect(t, addr, relayKey)

	deadline := time.Now().Add(3 * time.Second)
	for srv.ConnectedCount() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("the relay kept a client that had gone silent")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
