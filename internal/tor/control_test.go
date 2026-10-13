package tor

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"
)

// fakeControl answers each command line it reads with the canned reply for
// it, and records what it was sent.
func fakeControl(t *testing.T, replies map[string]string) (*controlConn, *[]string) {
	t.Helper()
	client, server := net.Pipe()
	var got []string
	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			got = append(got, line)
			verb, _, _ := strings.Cut(line, " ")
			reply, ok := replies[line]
			if !ok {
				reply, ok = replies[verb]
			}
			if !ok {
				reply = "510 Unrecognized command\r\n"
			}
			if _, err := server.Write([]byte(reply)); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { client.Close() })
	return &controlConn{conn: client, r: bufio.NewReader(client)}, &got
}

func TestGetinfo(t *testing.T) {
	c, _ := fakeControl(t, map[string]string{
		"GETINFO net/listeners/socks": "250-net/listeners/socks=\"127.0.0.1:41234\"\r\n250 OK\r\n",
	})
	v, err := c.getinfo("net/listeners/socks")
	if err != nil {
		t.Fatal(err)
	}
	if unquote(strings.Fields(v)[0]) != "127.0.0.1:41234" {
		t.Errorf("got %q", v)
	}
}

func TestDataReply(t *testing.T) {
	c, _ := fakeControl(t, map[string]string{
		"GETINFO config-text": "250+config-text=\r\nDataDirectory /x\r\n..dotted\r\n.\r\n250 OK\r\n",
	})
	v, err := c.getinfo("config-text")
	if err != nil {
		t.Fatal(err)
	}
	if v != "DataDirectory /x\n.dotted" {
		t.Errorf("got %q", v)
	}
}

func TestRefusalSaysWhy(t *testing.T) {
	c, _ := fakeControl(t, map[string]string{
		"AUTHENTICATE": "515 Authentication failed: Wrong length on authentication cookie.\r\n",
	})
	err := c.authenticate([]byte("short"))
	var r *errReply
	if !errors.As(err, &r) || r.code != 515 || !strings.Contains(r.msg, "Wrong length") {
		t.Fatalf("got %v", err)
	}
}

func TestAddOnionNamesTheService(t *testing.T) {
	id := strings.TrimSuffix(fixedHost, ".onion")
	c, got := fakeControl(t, map[string]string{
		"ADD_ONION": "250-ServiceID=" + id + "\r\n250 OK\r\n",
	})
	sid, err := c.addOnion(fixedKey(), 80, "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	if sid != id {
		t.Errorf("service id %q", sid)
	}
	want := "ADD_ONION " + fixedKey().blob() + " Port=80,127.0.0.1:9999"
	if (*got)[0] != want {
		t.Errorf("sent %q, want %q", (*got)[0], want)
	}
}

func TestParseBootstrap(t *testing.T) {
	b, err := parseBootstrap(`NOTICE BOOTSTRAP PROGRESS=85 TAG=ap_handshake_done SUMMARY="Connected to a relay to build circuits"`)
	if err != nil {
		t.Fatal(err)
	}
	if b.Progress != 85 || b.Summary != "Connected to a relay to build circuits" {
		t.Errorf("got %+v", b)
	}
	b, err = parseBootstrap(`WARN BOOTSTRAP PROGRESS=10 TAG=conn_done SUMMARY="Connected to a relay" WARNING="Connection refused" REASON=CONNECTREFUSED COUNT=3 RECOMMENDATION=warn`)
	if err != nil || b.Progress != 10 {
		t.Errorf("got %+v, %v", b, err)
	}
	if _, err := parseBootstrap("NOTICE BOOTSTRAP TAG=starting"); err == nil {
		t.Error("no progress parsed as some")
	}
}
