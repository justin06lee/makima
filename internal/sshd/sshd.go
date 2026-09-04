// Package sshd is a small SSH server that only ever listens on the mesh.
//
// makima already shells into other machines — `makima ssh` finds the address
// and hands off to the system client. That works right up until the far end
// has no sshd, which on a laptop is the normal case: macOS ships Remote Login
// switched off, most desktop Linux installs do not run one, and turning it on
// means opening a service to every network the machine is ever on.
//
// This is the narrow version of that. It binds the node's mesh address and
// nothing else, so it is reachable by peers and by nothing else — not the LAN,
// not localhost, not the internet. There is no password authentication and no
// way to add one. There is exactly one local account it will ever run as, and
// it is chosen on this machine rather than by whoever connects.
//
// The host key is derived from the machine key rather than stored. A node
// already has a permanent identity; generating a second one would mean another
// secret on disk, another thing to lose, and a host-key warning the first time
// somebody reinstalls. Deriving it means the fingerprint follows the machine's
// identity, which is what a person checking it actually means to verify.
package sshd

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/justin06lee/makima/internal/key"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

// DefaultPort is where the server listens on the mesh address.
//
// Not 22. A system sshd bound to 0.0.0.0:22 already owns port 22 on every
// address including this one, so binding there would fail on exactly the
// machines where both are wanted. 2222 is the conventional alternative, it is
// only reachable over the mesh anyway, and `makima ssh` fills it in so nobody
// has to type it.
const DefaultPort = 2222

// hostKeyInfo separates this derivation from every other use of the machine
// key, so the SSH host key cannot be confused with — or substituted for — any
// other key material derived from the same secret.
const hostKeyInfo = "makima ssh host key v1"

// newHash is the hash HKDF runs on. Named rather than inlined so the one place
// it is chosen is obvious.
func newHash() hash.Hash { return sha256.New() }

// HostKey derives this machine's SSH host key from its machine key.
//
// Deterministic, so it survives restarts and reinstalls of makima without a
// host-key warning, and distinct per machine because the machine key is. HKDF
// rather than a plain hash: it is the standard answer to "turn one secret into
// another, unrelated one", and the info string is what makes "unrelated"
// checkable.
func HostKey(machineKey key.Private) (ssh.Signer, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(hkdf.New(newHash, machineKey[:], nil, []byte(hostKeyInfo)), seed); err != nil {
		return nil, fmt.Errorf("sshd: derive host key: %w", err)
	}
	return ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
}

// Config is everything the server needs, resolved by its caller.
type Config struct {
	// Addr is the mesh address to bind. The server listens here and nowhere
	// else, which is the entire access control story.
	Addr netip.Addr

	// Port defaults to DefaultPort.
	Port uint16

	// HostKey identifies this machine to clients.
	HostKey ssh.Signer

	// Authorized is consulted for every public key offered. It is a function
	// rather than a list so the set can be refreshed — from a file that
	// changed, or from a GitHub account — without restarting the listener or
	// disturbing an open session.
	Authorized func(ssh.PublicKey) bool

	// User is the local account every session runs as.
	//
	// Chosen here, never by the client. A daemon that runs as root and takes
	// the SSH username at face value is a root shell for anyone holding an
	// authorized key, and no amount of care elsewhere makes that acceptable.
	User *SessionUser

	Logger *log.Logger
}

// SessionUser is the account a shell runs as.
type SessionUser struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

// Server is a running SSH listener.
type Server struct {
	log *log.Logger

	mu      sync.Mutex
	ln      net.Listener
	cfg     Config
	bound   netip.AddrPort
	started time.Time

	sessions atomic64
}

// New builds a server. It does not listen until Apply.
func New(logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{log: logger}
}

// ErrUnsupported reports a platform where sessions cannot be run.
var ErrUnsupported = errors.New("sshd: not supported on this platform")

// Apply starts, restarts or stops the server to match cfg.
//
// Idempotent: called on every settings change and every netmap, and does
// nothing when the address and port are unchanged. Rebinding drops open
// sessions, so it only happens when something that actually requires it moved.
func (s *Server) Apply(cfg Config) error {
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Logger == nil {
		cfg.Logger = s.log
	}

	want := netip.AddrPortFrom(cfg.Addr, cfg.Port)

	s.mu.Lock()
	// The callbacks and the user can be swapped underneath a live listener:
	// re-reading an authorized_keys file must not kick anybody off.
	s.cfg = cfg

	if s.ln != nil && s.bound == want && cfg.Addr.IsValid() {
		s.mu.Unlock()
		return nil
	}

	old := s.ln
	s.ln = nil
	s.mu.Unlock()

	if old != nil {
		old.Close()
	}
	if !cfg.Addr.IsValid() {
		return nil
	}
	if cfg.HostKey == nil {
		return errors.New("sshd: no host key")
	}
	if cfg.User == nil {
		return errors.New("sshd: no account to run sessions as")
	}
	if err := supported(); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", want.String())
	if err != nil {
		return fmt.Errorf("sshd: listen on %s: %w", want, err)
	}

	s.mu.Lock()
	s.ln = ln
	s.bound = want
	s.started = time.Now()
	s.mu.Unlock()

	s.log.Printf("ssh on %s as %s — fingerprint %s", want, cfg.User.Name, ssh.FingerprintSHA256(cfg.HostKey.PublicKey()))
	go s.accept(ln)
	return nil
}

// Close stops the server.
func (s *Server) Close() {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.bound = netip.AddrPort{}
	s.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
}

// Status reports whether the server is running and where.
func (s *Server) Status() (addr netip.AddrPort, active bool, fingerprint string, sessions uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ln == nil {
		return netip.AddrPort{}, false, "", s.sessions.get()
	}
	fp := ""
	if s.cfg.HostKey != nil {
		fp = ssh.FingerprintSHA256(s.cfg.HostKey.PublicKey())
	}
	return s.bound, true, fp, s.sessions.get()
}

func (s *Server) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			// A closed listener is Apply or Close doing their job.
			return
		}
		go s.handle(c)
	}
}

// handshakeTimeout bounds how long a connection may take to authenticate.
//
// Without it, opening a socket and saying nothing holds a goroutine
// indefinitely — the cheapest possible way to exhaust a server, and one that
// does not require any credential at all.
const handshakeTimeout = 30 * time.Second

func (s *Server) handle(c net.Conn) {
	defer c.Close()

	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()

	var authorizedKey ssh.PublicKey

	sc := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) {
			if cfg.Authorized == nil || !cfg.Authorized(pub) {
				// One error for every rejection. A client learns whether a key
				// was accepted, which is unavoidable, and nothing else.
				return nil, errors.New("key not authorized")
			}
			authorizedKey = pub
			return &ssh.Permissions{}, nil
		},
		// No password callback at all, rather than one that always fails:
		// a server that advertises password authentication invites people to
		// try guessing, and there is nothing here to guess.
		ServerVersion: "SSH-2.0-makima",
	}
	sc.AddHostKey(cfg.HostKey)

	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	conn, chans, reqs, err := ssh.NewServerConn(c, sc)
	if err != nil {
		// Failed handshakes are routine — a port scan, a client with the
		// wrong key — and logging every one would be a torrent.
		return
	}
	defer conn.Close()

	// The handshake is done; a session may now last as long as it likes.
	_ = c.SetDeadline(time.Time{})

	s.log.Printf("ssh: session from %s (%s)", conn.RemoteAddr(), ssh.FingerprintSHA256(authorizedKey))
	s.sessions.inc()

	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		if ch.ChannelType() != "session" {
			// Notably absent: direct-tcpip. Port forwarding through this
			// server would be a second, much broader hole than a shell, and
			// makima already forwards ports as a first-class thing that shows
			// up in status and obeys the mesh's access control.
			_ = ch.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		go s.session(ch, cfg)
	}
}

// atomic64 is a counter guarded by the server's own mutex, kept as a type so
// the intent reads at the call site.
type atomic64 struct{ n uint64 }

func (a *atomic64) inc()        { a.n++ }
func (a *atomic64) get() uint64 { return a.n }
