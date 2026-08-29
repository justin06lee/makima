// Package portmap asks the local router to forward a port to this machine.
//
// STUN can tell a node what its public address is; it cannot make that address
// reachable. Behind an address-dependent NAT the mapping STUN reveals only
// accepts packets from the server that created it, so a peer aiming at it is
// dropped. A port mapping is the difference: it asks the router, in as many
// words, to send anything arriving on a public port to this machine — and once
// it agrees, the node is directly reachable from anywhere, relay and hole
// punching both unnecessary.
//
// Two protocols are spoken, both to the default gateway over UDP:
//
//	NAT-PMP  RFC 6886, Apple's. Small, ubiquitous on consumer gear.
//	PCP      RFC 6887, its successor. Same port, compatible enough to try
//	         both without a second round of discovery.
//
// UPnP IGD is deliberately not implemented. It would require SSDP multicast
// discovery and then SOAP-over-HTTP with an XML device description, which is
// several hundred lines of parsing for a protocol whose share of routers is
// shrinking — and every router that speaks only UPnP still works through the
// relay. It is the one place in makima where the effort is not worth the tail.
package portmap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// gatewayPort is where both protocols listen on the router.
const gatewayPort = 5351

// mappingLifetime is how long a mapping is requested for.
//
// Two hours is long enough that renewals are rare and short enough that a
// router rebooting into a clean state does not leave a stale mapping pointing
// at whoever next gets this machine's DHCP lease. Renewal happens at half
// this, which is what both RFCs recommend.
const mappingLifetime = 2 * time.Hour

// requestTimeout bounds one attempt. Routers that speak neither protocol
// simply do not answer, and that is the common case — so it needs to be short.
const requestTimeout = 500 * time.Millisecond

// attempts is how many times a request is repeated before giving up.
//
// UDP to a router that is busy can be dropped, and the difference between
// "does not support this" and "dropped one packet" is only visible by asking
// twice.
const attempts = 3

// Client maintains a port mapping on the local router.
type Client struct {
	log *log.Logger

	mu       sync.Mutex
	external netip.AddrPort
	haveMap  bool
	internal uint16
	proto    string
	expires  time.Time
}

// New builds a port mapper.
func New(logger *log.Logger) *Client {
	if logger == nil {
		logger = log.Default()
	}
	return &Client{log: logger}
}

// External reports the mapped public address, if a mapping is currently held.
func (c *Client) External() (netip.AddrPort, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.haveMap || time.Now().After(c.expires) {
		return netip.AddrPort{}, false
	}
	return c.external, true
}

// Protocol reports which protocol produced the current mapping, for status
// output.
func (c *Client) Protocol() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.proto
}

// ErrNoGateway reports that no default gateway could be found.
var ErrNoGateway = errors.New("portmap: no default gateway")

// ErrUnsupported reports a router that answered neither protocol.
var ErrUnsupported = errors.New("portmap: the router does not support NAT-PMP or PCP")

// Map requests a mapping for the given local port, returning the public
// address it produced.
//
// PCP is tried first and NAT-PMP second. A PCP-capable router answers PCP; a
// NAT-PMP-only one either ignores the PCP request or rejects it with an
// unsupported-version error, both of which fall through cheaply. Doing it the
// other way round would mean a modern router never exercising its better
// protocol.
func (c *Client) Map(ctx context.Context, localPort uint16) (netip.AddrPort, error) {
	if localPort == 0 {
		return netip.AddrPort{}, errors.New("portmap: no local port to map")
	}

	gw, err := Gateway()
	if err != nil {
		return netip.AddrPort{}, err
	}

	if ext, err := c.pcpMap(ctx, gw, localPort); err == nil {
		c.record(ext, localPort, "pcp")
		return ext, nil
	}
	if ext, err := c.natpmpMap(ctx, gw, localPort); err == nil {
		c.record(ext, localPort, "nat-pmp")
		return ext, nil
	}

	c.mu.Lock()
	c.haveMap = false
	c.mu.Unlock()
	return netip.AddrPort{}, ErrUnsupported
}

func (c *Client) record(ext netip.AddrPort, internal uint16, proto string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.haveMap || c.external != ext {
		c.log.Printf("portmap: %s mapped %s -> :%d", proto, ext, internal)
	}
	c.external = ext
	c.internal = internal
	c.haveMap = true
	c.proto = proto
	// Renew at half the lifetime, as both RFCs advise: it leaves a full
	// lifetime of margin for a renewal that gets dropped.
	c.expires = time.Now().Add(mappingLifetime / 2)
}

// Close releases the mapping.
//
// Best-effort. A mapping left behind expires on its own, so failing to tear it
// down costs a stale forward for at most its lifetime — worth one attempt, not
// worth blocking shutdown over.
func (c *Client) Close() {
	c.mu.Lock()
	held := c.haveMap
	internal := c.internal
	proto := c.proto
	c.haveMap = false
	c.mu.Unlock()

	if !held {
		return
	}

	gw, err := Gateway()
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if proto == "pcp" {
		_ = c.pcpDelete(ctx, gw, internal)
		return
	}
	_ = c.natpmpDelete(ctx, gw, internal)
}

// --- NAT-PMP (RFC 6886) -------------------------------------------------

// natpmpMap requests a UDP mapping and reads back the external address.
//
// Two round trips: one for the external address, one for the mapping. They are
// separate opcodes in the protocol and there is no combined form.
func (c *Client) natpmpMap(ctx context.Context, gw netip.Addr, localPort uint16) (netip.AddrPort, error) {
	// Opcode 0: what is your external address?
	resp, err := exchange(ctx, gw, []byte{0, 0})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(resp) < 12 || resp[0] != 0 || resp[1] != 128 {
		return netip.AddrPort{}, errors.New("portmap: malformed NAT-PMP address response")
	}
	if code := binary.BigEndian.Uint16(resp[2:4]); code != 0 {
		return netip.AddrPort{}, fmt.Errorf("portmap: NAT-PMP returned result code %d", code)
	}
	external := netip.AddrFrom4([4]byte(resp[8:12]))

	// Opcode 1: map a UDP port. Requesting the same external port as the
	// internal one is a hint, not a demand; the router's answer is what counts.
	req := make([]byte, 12)
	req[0] = 0 // version
	req[1] = 1 // map UDP
	binary.BigEndian.PutUint16(req[4:6], localPort)
	binary.BigEndian.PutUint16(req[6:8], localPort)
	binary.BigEndian.PutUint32(req[8:12], uint32(mappingLifetime.Seconds()))

	resp, err = exchange(ctx, gw, req)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(resp) < 16 || resp[1] != 129 {
		return netip.AddrPort{}, errors.New("portmap: malformed NAT-PMP mapping response")
	}
	if code := binary.BigEndian.Uint16(resp[2:4]); code != 0 {
		return netip.AddrPort{}, fmt.Errorf("portmap: NAT-PMP refused the mapping (code %d)", code)
	}

	externalPort := binary.BigEndian.Uint16(resp[10:12])
	return netip.AddrPortFrom(external, externalPort), nil
}

// natpmpDelete removes a mapping by requesting it with a zero lifetime.
func (c *Client) natpmpDelete(ctx context.Context, gw netip.Addr, localPort uint16) error {
	req := make([]byte, 12)
	req[1] = 1
	binary.BigEndian.PutUint16(req[4:6], localPort)
	// External port and lifetime both zero: the RFC's way of saying "remove".
	_, err := exchange(ctx, gw, req)
	return err
}

// --- PCP (RFC 6887) -----------------------------------------------------

// pcpMap requests a mapping using PCP's single MAP opcode.
func (c *Client) pcpMap(ctx context.Context, gw netip.Addr, localPort uint16) (netip.AddrPort, error) {
	self, err := localAddrTowards(gw)
	if err != nil {
		return netip.AddrPort{}, err
	}

	req, nonce := pcpMapRequest(self, localPort, uint32(mappingLifetime.Seconds()))
	resp, err := exchange(ctx, gw, req)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return parsePCPMapResponse(resp, nonce)
}

func (c *Client) pcpDelete(ctx context.Context, gw netip.Addr, localPort uint16) error {
	self, err := localAddrTowards(gw)
	if err != nil {
		return err
	}
	req, _ := pcpMapRequest(self, localPort, 0)
	_, err = exchange(ctx, gw, req)
	return err
}

// pcpMapRequest builds a MAP request.
//
// The nonce is what makes PCP safe on a shared network: it is echoed in the
// response and required on any later request touching the same mapping, so
// another host on the LAN cannot delete or repoint a mapping it did not
// create.
func pcpMapRequest(self netip.Addr, localPort uint16, lifetime uint32) ([]byte, [12]byte) {
	b := make([]byte, 60)

	b[0] = 2 // version
	b[1] = 1 // opcode MAP, request
	binary.BigEndian.PutUint32(b[4:8], lifetime)
	copy(b[8:24], to16(self))

	var nonce [12]byte
	// Derived from the port rather than random: a renewal has to present the
	// same nonce, and deriving it means no state has to survive a restart for
	// the mapping to remain ours.
	binary.BigEndian.PutUint16(nonce[0:2], localPort)
	copy(nonce[2:], "makima")
	copy(b[24:36], nonce[:])

	b[36] = 17 // protocol UDP
	binary.BigEndian.PutUint16(b[40:42], localPort)
	binary.BigEndian.PutUint16(b[42:44], localPort)
	// Suggested external address all-zero: no preference.
	return b, nonce
}

func parsePCPMapResponse(resp []byte, nonce [12]byte) (netip.AddrPort, error) {
	if len(resp) < 60 {
		return netip.AddrPort{}, errors.New("portmap: PCP response too short")
	}
	if resp[0] != 2 {
		return netip.AddrPort{}, fmt.Errorf("portmap: PCP version %d in response", resp[0])
	}
	if resp[1] != 0x81 { // MAP, response bit set
		return netip.AddrPort{}, errors.New("portmap: not a PCP MAP response")
	}
	if code := resp[3]; code != 0 {
		return netip.AddrPort{}, fmt.Errorf("portmap: PCP refused the mapping (result %d)", code)
	}
	if [12]byte(resp[24:36]) != nonce {
		return netip.AddrPort{}, errors.New("portmap: PCP nonce mismatch")
	}

	externalPort := binary.BigEndian.Uint16(resp[42:44])
	addr, ok := netip.AddrFromSlice(resp[44:60])
	if !ok {
		return netip.AddrPort{}, errors.New("portmap: malformed PCP external address")
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.AddrPort{}, errors.New("portmap: PCP returned no external address")
	}
	return netip.AddrPortFrom(addr, externalPort), nil
}

// to16 renders an address as PCP's 16-byte field, mapping IPv4 into the
// v4-mapped range as the RFC requires.
func to16(a netip.Addr) []byte {
	b := a.As16()
	return b[:]
}

// --- transport ----------------------------------------------------------

// exchange sends a request to the gateway and waits for a reply, retrying a
// few times before concluding the router is not listening.
func exchange(ctx context.Context, gw netip.Addr, req []byte) ([]byte, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: gw.AsSlice(), Port: gatewayPort})
	if err != nil {
		return nil, fmt.Errorf("portmap: dial gateway: %w", err)
	}
	defer conn.Close()

	buf := make([]byte, 1100)
	var lastErr error

	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		deadline := time.Now().Add(requestTimeout << uint(i))
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}

		if _, err := conn.Write(req); err != nil {
			lastErr = err
			continue
		}
		n, err := conn.Read(buf)
		if err != nil {
			lastErr = err
			continue
		}
		return append([]byte(nil), buf[:n]...), nil
	}

	if lastErr == nil {
		lastErr = errors.New("no response")
	}
	return nil, fmt.Errorf("portmap: gateway %s: %w", gw, lastErr)
}

// localAddrTowards reports the address this host would use to reach a target.
//
// A UDP "connection" sends nothing; it only asks the kernel to pick a route
// and bind a source address. That is exactly the question being asked, and it
// answers it without any traffic or any dependency on the target existing.
func localAddrTowards(target netip.Addr) (netip.Addr, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: target.AsSlice(), Port: gatewayPort})
	if err != nil {
		return netip.Addr{}, fmt.Errorf("portmap: find local address: %w", err)
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("portmap: unexpected local address type")
	}
	addr, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return netip.Addr{}, errors.New("portmap: malformed local address")
	}
	return addr.Unmap(), nil
}
