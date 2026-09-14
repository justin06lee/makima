package dnsserver

import (
	"net"
	"testing"
	"time"
)

// The loopback listener answers over a real socket, from the same zone, on a
// port of the kernel's choosing — what /etc/resolver on a Mac is pointed at.
func TestLoopbackAnswers(t *testing.T) {
	s := testServer(t)
	defer s.Close()

	ap, err := s.ListenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	if !ap.Addr().IsLoopback() || ap.Port() == 0 || s.Loopback() != ap {
		t.Fatalf("listening on %s, Loopback() = %s", ap, s.Loopback())
	}

	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ap))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := c.Write(askFor("desktop.makima", typeA)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxMessage)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer on loopback: %v", err)
	}
	if got := firstAnswerA(t, buf[:n]); got.String() != "100.64.0.2" {
		t.Errorf("desktop.makima resolved to %s over loopback, want 100.64.0.2", got)
	}
}
