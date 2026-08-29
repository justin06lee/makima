package wg

import (
	"golang.zx2c4.com/wireguard/tun"
)

// InboundFilter decides whether a decrypted packet may reach the host.
type InboundFilter func(packet []byte) bool

// filteredTUN applies a policy to packets on their way out of the tunnel.
//
// Wrapping the TUN device rather than filtering inside WireGuard, because this
// is the only point where every inbound packet has been decrypted, attributed
// to a peer by cryptokey routing, and not yet handed to the kernel. Filtering
// earlier would mean inspecting ciphertext; later would mean the packet has
// already been delivered.
//
// Only Write is filtered. Write carries packets *into* the host — traffic
// arriving from peers — and Read carries the host's own outbound traffic,
// which is not what a policy about who may reach this machine has anything to
// say about. Enforcing on ingress is also the only enforcement that means
// anything: a compromised sender will not filter itself.
type filteredTUN struct {
	tun.Device
	allow InboundFilter
}

// Write delivers the packets the filter permits and silently drops the rest.
//
// Silently, because the alternative is worse. Returning an error would make
// wireguard-go treat a policy decision as a device failure and tear the
// interface down, so one denied packet would take the whole tunnel with it.
// The count of what was dropped lives in the policy guard, which is where
// somebody debugging a rule will actually look.
func (f *filteredTUN) Write(bufs [][]byte, offset int) (int, error) {
	// The overwhelming majority of batches are entirely permitted, so check
	// first and forward the caller's own slice when nothing has to go. That
	// keeps the common path free of both allocation and copying.
	blocked := -1
	for i, b := range bufs {
		if offset > len(b) || !f.allow(b[offset:]) {
			blocked = i
			break
		}
	}
	if blocked < 0 {
		return f.Device.Write(bufs, offset)
	}

	// Something has to be dropped. Compacting in place would be cheaper, but
	// bufs belongs to the caller, and a Write that reorders its argument is a
	// trap for whatever recycles those buffers afterwards.
	kept := make([][]byte, 0, len(bufs))
	kept = append(kept, bufs[:blocked]...)
	for _, b := range bufs[blocked+1:] {
		if offset > len(b) || !f.allow(b[offset:]) {
			continue
		}
		kept = append(kept, b)
	}

	if len(kept) == 0 {
		// Report every packet as handled. wireguard-go compares the count
		// against what it submitted and logs a short write as an error, and a
		// filter doing its job is not an error.
		return len(bufs), nil
	}

	if _, err := f.Device.Write(kept, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}
