package wg

import (
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// recordingTUN captures what actually reached the host.
type recordingTUN struct {
	tun.Device
	written [][]byte
}

func (r *recordingTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		r.written = append(r.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func packets(vals ...byte) [][]byte {
	out := make([][]byte, 0, len(vals))
	for _, v := range vals {
		out = append(out, []byte{0, v})
	}
	return out
}

// allowAllBut permits everything except the given marker byte.
func allowAllBut(drop byte) InboundFilter {
	return func(p []byte) bool { return len(p) > 0 && p[0] != drop }
}

func TestFilterPassesPermittedPackets(t *testing.T) {
	rec := &recordingTUN{}
	f := &filteredTUN{Device: rec, allow: func([]byte) bool { return true }}

	in := packets(1, 2, 3)
	n, err := f.Write(in, 1)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || len(rec.written) != 3 {
		t.Errorf("wrote %d, delivered %d, want 3 and 3", n, len(rec.written))
	}
}

func TestFilterDropsDeniedPackets(t *testing.T) {
	rec := &recordingTUN{}
	f := &filteredTUN{Device: rec, allow: allowAllBut(2)}

	n, err := f.Write(packets(1, 2, 3), 1)
	if err != nil {
		t.Fatal(err)
	}

	// The caller is told everything was handled: a filtered packet is not a
	// short write, and reporting one would make wireguard-go log an error.
	if n != 3 {
		t.Errorf("reported %d packets handled, want 3", n)
	}
	if len(rec.written) != 2 {
		t.Fatalf("delivered %d packets, want 2", len(rec.written))
	}
	for _, b := range rec.written {
		if b[0] == 2 {
			t.Error("a denied packet reached the host")
		}
	}
}

// The caller's slice belongs to the caller. Compacting it in place would be
// cheaper and would be a trap for whatever recycles those buffers afterwards.
func TestFilterDoesNotMutateTheCallersSlice(t *testing.T) {
	rec := &recordingTUN{}
	f := &filteredTUN{Device: rec, allow: allowAllBut(1)}

	in := packets(1, 2, 3)
	before := make([][]byte, len(in))
	copy(before, in)

	if _, err := f.Write(in, 1); err != nil {
		t.Fatal(err)
	}

	for i := range in {
		if &in[i][0] != &before[i][0] {
			t.Fatalf("element %d was replaced; the caller's slice was compacted in place", i)
		}
	}
}

func TestFilterDroppingEverything(t *testing.T) {
	rec := &recordingTUN{}
	f := &filteredTUN{Device: rec, allow: func([]byte) bool { return false }}

	n, err := f.Write(packets(1, 2), 1)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("reported %d handled, want 2", n)
	}
	if len(rec.written) != 0 {
		t.Errorf("%d packets reached the host despite a deny-all filter", len(rec.written))
	}
}

// A buffer shorter than the offset cannot be inspected, and something that
// cannot be classified must not be delivered.
func TestFilterDropsUninspectablePackets(t *testing.T) {
	rec := &recordingTUN{}
	f := &filteredTUN{Device: rec, allow: func([]byte) bool { return true }}

	if _, err := f.Write([][]byte{{}}, 4); err != nil {
		t.Fatal(err)
	}
	if len(rec.written) != 0 {
		t.Error("a packet shorter than the offset was delivered")
	}
}

// sendingTUN hands out a fixed batch as if the host had sent it.
type sendingTUN struct {
	tun.Device
	out [][]byte
}

func (s *sendingTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for i, p := range s.out {
		sizes[i] = copy(bufs[i][offset:], p)
	}
	return len(s.out), nil
}

// The observer sees exactly what the host sent — each packet, at its real
// length, without the headroom wireguard-go leaves in front of it.
func TestOutboundObserverSeesWhatTheHostSent(t *testing.T) {
	var seen [][]byte
	f := &filteredTUN{
		Device: &sendingTUN{out: [][]byte{{1, 2, 3}, {4}}},
		allow:  func([]byte) bool { return true },
		saw:    func(p []byte) { seen = append(seen, append([]byte(nil), p...)) },
	}
	const offset = 16
	bufs := [][]byte{make([]byte, 64), make([]byte, 64)}
	sizes := make([]int, 2)
	n, err := f.Read(bufs, sizes, offset)
	if err != nil || n != 2 {
		t.Fatalf("read %d, %v", n, err)
	}
	if len(seen) != 2 || string(seen[0]) != "\x01\x02\x03" || string(seen[1]) != "\x04" {
		t.Errorf("observer saw %v", seen)
	}
}
