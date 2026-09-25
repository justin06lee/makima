package control

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"
)

// occupy makes sure something is listening on port — this test, or
// whatever already was.
func occupy(t *testing.T, port int) {
	t.Helper()
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return // taken already, which is the point
	}
	t.Cleanup(func() { l.Close() })
}

// A new network's server takes the first free port from the default and
// writes it down; after that, it is the port.
func TestANewServerPicksAndRecordsItsPort(t *testing.T) {
	state := filepath.Join(t.TempDir(), "control.json")
	occupy(t, DefaultPort) // tenet's case: 8080 already had a server on it

	ln, port, err := ListenControl(state, "", false)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if port == DefaultPort {
		t.Fatal("took a port that was in use")
	}
	if got := RecordedPort(state); got != port {
		t.Errorf("recorded %d, listened on %d", got, port)
	}

	// The next start comes back to it, even with the default now free.
	ln, again, err := ListenControl(state, "", false)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if again != port {
		t.Errorf("came back on %d, not %d", again, port)
	}
}

// Once the network exists its port does not wander: every machine in it
// holds it. Taken by something else, the server says so rather than move.
func TestARecordedPortIsNotAbandoned(t *testing.T) {
	state := filepath.Join(t.TempDir(), "control.json")
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	taken := l.Addr().(*net.TCPAddr).Port
	defer l.Close()
	if err := RecordPort(state, taken); err != nil {
		t.Fatal(err)
	}
	if ln, port, err := ListenControl(state, "", false); err == nil {
		ln.Close()
		t.Errorf("moved to %d when its recorded port was taken", port)
	}
}

// An address given explicitly is used, and becomes the record, so every
// other part of makima asking afterwards hears the same port.
func TestAnExplicitAddressIsRecorded(t *testing.T) {
	state := filepath.Join(t.TempDir(), "control.json")
	ln, port, err := ListenControl(state, "127.0.0.1:0", false)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if RecordedPort(state) != port {
		t.Errorf("recorded %d, listened on %d", RecordedPort(state), port)
	}
}

// A network from before the port was recorded listened on DefaultPort, and
// its machines look for it there; it does not go looking for another.
func TestAnOlderNetworkStaysOnTheDefault(t *testing.T) {
	state := filepath.Join(t.TempDir(), "control.json")
	l, err := net.Listen("tcp", ":"+strconv.Itoa(DefaultPort))
	if err != nil {
		// Taken already, as on this machine: exactly the case.
	} else {
		defer l.Close()
	}
	if ln, port, err := ListenControl(state, "", true); err == nil {
		ln.Close()
		t.Errorf("an established network moved to %d when %d was busy", port, DefaultPort)
	}
}
