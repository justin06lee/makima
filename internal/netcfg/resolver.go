package netcfg

import (
	"net/netip"
	"sync"
)

// Resolver registers the mesh's DNS server with the operating system, for the
// mesh domain and nothing else.
//
// Split DNS rather than taking over resolution entirely. Pointing the system
// at a mesh resolver for *all* names is how a VPN ends up breaking a machine's
// internet the moment the tunnel drops, and how it ends up leaking every
// lookup the user makes to whoever runs the mesh. Registering for one suffix
// means `ssh laptop.makima` works, nothing else changes, and a crashed daemon
// costs mesh names rather than all names.
//
// Every platform stores this somewhere different and none of them is a file
// with a stable format, which is why this is a seam with three
// implementations rather than one clever one.
type Resolver struct {
	iface string

	mu        sync.Mutex
	installed bool
	domain    string
	server    netip.Addr
}

// NewResolver builds a resolver manager for an interface.
func NewResolver(iface string) *Resolver { return &Resolver{iface: iface} }

// Set points the OS at server for names under domain.
//
// Idempotent: re-registering the same pair does nothing, which matters because
// this is called on every netmap update and the platform tools are neither
// fast nor silent.
func (r *Resolver) Set(domain string, server netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.installed && r.domain == domain && r.server == server {
		return nil
	}
	if err := setResolver(r.iface, domain, server); err != nil {
		return err
	}
	r.installed = true
	r.domain = domain
	r.server = server
	return nil
}

// Close removes the registration.
//
// Called on shutdown, and it genuinely matters: a resolver entry pointing at a
// tunnel address that no longer exists makes every mesh name lookup hang for
// the resolver's full timeout, which reads to a user as "the whole machine
// went slow" rather than "the VPN stopped".
func (r *Resolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.installed {
		return nil
	}
	err := clearResolver(r.iface, r.domain)
	r.installed = false
	return err
}
