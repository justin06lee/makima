package disco

import (
	"net/netip"
	"testing"

	"github.com/justin06lee/makima/internal/key"
)

func keys(t *testing.T) (a, b key.Private) {
	t.Helper()
	var err error
	if a, err = key.NewPrivate(); err != nil {
		t.Fatal(err)
	}
	if b, err = key.NewPrivate(); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestPingRoundTrip(t *testing.T) {
	sender, recipient := keys(t)

	nodeKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	want := &Ping{TxID: TxID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, NodeKey: nodeKey.Public()}

	pkt, err := Seal(want, recipient.Public(), sender)
	if err != nil {
		t.Fatal(err)
	}

	from, msg, err := Open(pkt, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if from != sender.Public() {
		t.Error("the opened packet did not name the actual sender")
	}

	got, ok := msg.(*Ping)
	if !ok {
		t.Fatalf("decoded a %T, want *Ping", msg)
	}
	if got.TxID != want.TxID {
		t.Errorf("txid %x, want %x", got.TxID, want.TxID)
	}
	if got.NodeKey != want.NodeKey {
		t.Error("the node key did not survive the round trip")
	}
}

func TestPongRoundTrip(t *testing.T) {
	sender, recipient := keys(t)

	for _, addr := range []string{"192.0.2.10:51820", "[2001:db8::1]:51820"} {
		want := &Pong{TxID: TxID{9}, Src: netip.MustParseAddrPort(addr)}

		pkt, err := Seal(want, recipient.Public(), sender)
		if err != nil {
			t.Fatal(err)
		}
		_, msg, err := Open(pkt, recipient)
		if err != nil {
			t.Fatal(err)
		}

		got, ok := msg.(*Pong)
		if !ok {
			t.Fatalf("decoded a %T, want *Pong", msg)
		}
		if got.Src != want.Src {
			t.Errorf("src %s, want %s", got.Src, want.Src)
		}
	}
}

// The classifier runs on every inbound datagram, so it has to separate disco
// from WireGuard reliably and cheaply.
func TestIsDiscoPacket(t *testing.T) {
	sender, recipient := keys(t)

	pkt, err := Seal(&Ping{}, recipient.Public(), sender)
	if err != nil {
		t.Fatal(err)
	}
	if !IsDiscoPacket(pkt) {
		t.Error("a real disco packet was not recognised")
	}

	// WireGuard's four message types, each as it appears on the wire.
	for _, typ := range []byte{1, 2, 3, 4} {
		wg := make([]byte, 148)
		wg[0] = typ
		if IsDiscoPacket(wg) {
			t.Errorf("a WireGuard type-%d message was mistaken for disco", typ)
		}
	}

	if IsDiscoPacket(nil) || IsDiscoPacket([]byte("mak")) {
		t.Error("a short buffer was mistaken for disco")
	}
}

// A probe sealed to someone else must not open, or a node could be steered
// onto a path by a stranger.
func TestWrongRecipientCannotOpen(t *testing.T) {
	sender, recipient := keys(t)
	stranger, _ := keys(t)

	pkt, err := Seal(&Ping{}, recipient.Public(), sender)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(pkt, stranger); err == nil {
		t.Error("a probe opened under the wrong key")
	}
}

func TestTamperedPacketRejected(t *testing.T) {
	sender, recipient := keys(t)

	pkt, err := Seal(&Ping{TxID: TxID{7}}, recipient.Public(), sender)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the ciphertext, past the plaintext header.
	pkt[len(pkt)-1] ^= 0x01

	if _, _, err := Open(pkt, recipient); err == nil {
		t.Error("a tampered probe was accepted")
	}
}

// The sender key in the header is unauthenticated by construction. Rewriting
// it must make the packet fail to open rather than succeed under a lie.
func TestForgedSenderKeyFails(t *testing.T) {
	sender, recipient := keys(t)
	impostor, _ := keys(t)

	pkt, err := Seal(&Ping{}, recipient.Public(), sender)
	if err != nil {
		t.Fatal(err)
	}

	claimed := impostor.Public()
	copy(pkt[len(Magic):len(Magic)+key.Size], claimed[:])

	if _, _, err := Open(pkt, recipient); err == nil {
		t.Error("a packet claiming a sender key it does not hold was accepted")
	}
}

func TestSenderKeyReadsHeader(t *testing.T) {
	sender, recipient := keys(t)

	pkt, err := Seal(&Ping{}, recipient.Public(), sender)
	if err != nil {
		t.Fatal(err)
	}

	got, err := SenderKey(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got != sender.Public() {
		t.Error("the header did not carry the sender's key")
	}

	if _, err := SenderKey([]byte("not disco")); err == nil {
		t.Error("SenderKey accepted a non-disco packet")
	}
}

func TestTruncatedMessagesRejected(t *testing.T) {
	if _, err := decode(nil); err == nil {
		t.Error("an empty message decoded")
	}
	if _, err := decode([]byte{byte(TypePing)}); err == nil {
		t.Error("a ping with no transaction id decoded")
	}
	// A ping whose node key is cut short.
	short := append([]byte{byte(TypePing)}, make([]byte, TxIDLen+4)...)
	if _, err := decode(short); err == nil {
		t.Error("a ping with a truncated node key decoded")
	}
	// An unknown type must be refused rather than guessed at.
	unknown := append([]byte{99}, make([]byte, TxIDLen)...)
	if _, err := decode(unknown); err == nil {
		t.Error("an unknown message type decoded")
	}
}

// A knock is the one message in this package parsed from someone who is not
// yet a peer, so its codec has to survive everything that can be done to it.
func TestKnockRoundTrip(t *testing.T) {
	nodeKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	want := &Knock{
		TxID:    TxID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		NodeKey: nodeKey.Public(),
		Addr:    netip.MustParseAddr("100.64.7.9"),
		Name:    "laptop",
		Token:   []byte("thirty-two bytes of digest, near enough"),
		Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("203.0.113.9:51820"),
			netip.MustParseAddrPort("[2001:db8::1]:51820"),
		},
	}

	b, err := encode(want)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := msg.(*Knock)
	if !ok {
		t.Fatalf("decoded a %T, want *Knock", msg)
	}

	if got.TxID != want.TxID || got.NodeKey != want.NodeKey || got.Addr != want.Addr {
		t.Error("identity fields did not survive the round trip")
	}
	if got.Name != want.Name || string(got.Token) != string(want.Token) {
		t.Error("name or token did not survive the round trip")
	}
	if len(got.Endpoints) != 2 || got.Endpoints[0] != want.Endpoints[0] || got.Endpoints[1] != want.Endpoints[1] {
		t.Errorf("endpoints came back as %v, want %v", got.Endpoints, want.Endpoints)
	}
}

func TestKnockedRoundTrip(t *testing.T) {
	nodeKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}

	want := &Knocked{
		TxID:      TxID{9},
		NodeKey:   nodeKey.Public(),
		Addr:      netip.MustParseAddr("100.100.1.1"),
		Name:      "desktop",
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.4:41641")},
	}

	b, err := encode(want)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := msg.(*Knocked)
	if !ok {
		t.Fatalf("decoded a %T, want *Knocked", msg)
	}
	if got.NodeKey != want.NodeKey || got.Addr != want.Addr || got.Name != want.Name {
		t.Error("fields did not survive the round trip")
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0] != want.Endpoints[0] {
		t.Errorf("endpoints came back as %v", got.Endpoints)
	}
}

// A node that has no mesh address yet still has to be able to knock, so an
// invalid address must encode and decode as one rather than being rejected.
func TestKnockCarriesAnAbsentAddress(t *testing.T) {
	b, err := encode(&Knock{Token: []byte("t")})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.(*Knock); got.Addr.IsValid() {
		t.Errorf("an absent address came back as %s", got.Addr)
	}
}

// Truncation at every offset must produce an error, never a panic and never a
// half-populated message. This is the untrusted-input surface of the package.
func TestTruncatedKnockNeverPanics(t *testing.T) {
	nodeKey, err := key.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	full, err := encode(&Knock{
		NodeKey:   nodeKey.Public(),
		Addr:      netip.MustParseAddr("100.64.0.1"),
		Name:      "x",
		Token:     []byte("token"),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:1")},
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := range full {
		if _, err := decode(full[:i]); err == nil && i < len(full) {
			t.Errorf("a knock truncated to %d bytes decoded without error", i)
		}
	}
}

// The endpoint count is attacker-controlled and read before anything is
// allocated, so it has to be bounded by the format itself.
func TestKnockRefusesTooManyEndpoints(t *testing.T) {
	b := []byte{byte(TypeKnock)}
	b = append(b, make([]byte, TxIDLen)...)  // TxID
	b = append(b, make([]byte, key.Size)...) // NodeKey
	b = append(b, 0)                         // no address
	b = appendBytes(b, nil)                  // no name
	b = appendBytes(b, []byte("t"))          // token
	b = append(b, byte(maxEndpoints+1))      // more endpoints than allowed

	if _, err := decode(b); err == nil {
		t.Error("a knock claiming more endpoints than the limit was accepted")
	}
}

// Encoding silently caps rather than failing: a machine with an improbable
// number of interfaces should still be able to knock.
func TestKnockCapsEndpointsOnEncode(t *testing.T) {
	var eps []netip.AddrPort
	for i := range maxEndpoints + 8 {
		eps = append(eps, netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), uint16(1000+i)))
	}

	b, err := encode(&Knock{Token: []byte("t"), Endpoints: eps})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(msg.(*Knock).Endpoints); got != maxEndpoints {
		t.Errorf("encoded %d endpoints, want the cap of %d", got, maxEndpoints)
	}
}
