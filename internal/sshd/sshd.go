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
// way to add one. A session runs as the account this machine chose unless the
// client asks for another one — and asking is answered by that account's own
// authorized_keys, never by the username alone.
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
	"strings"
	"sync"
	"sync/atomic"
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

	// Authorized is consulted for the keys that open the default account. It
	// is a function rather than a list so the set can be refreshed — from a
	// file that changed, or from a GitHub account — without restarting the
	// listener or disturbing an open session.
	Authorized func(ssh.PublicKey, netip.Addr) (Grant, bool)

	// User is the account a session runs as when the client names no other,
	// and the one Authorized speaks for.
	User *SessionUser

	// Accounts lets a client ask for a different local account by SSH
	// username — root included. Nil keeps the server single-account.
	//
	// The username is a request, never a grant. It is honoured only when that
	// account's own authorized_keys holds the offered key, which is the same
	// question the system's sshd asks and the same file its administrator
	// already curates. What this must never become is a daemon that runs as
	// root and takes the username at face value: that is a root shell for
	// anyone holding any authorized key.
	//
	// The keys in Authorized deliberately do not carry over. A GitHub account
	// named as a key source says who may use this machine as its owner; it
	// does not say who may be root on it.
	Accounts Accounts

	Logger *log.Logger
}

// SessionUser is the account a shell runs as.
type SessionUser struct {
	Name string
	UID  int
	GID  int

	// Groups are the account's supplementary groups. Without them a session
	// would run with root's, or with none at all — and an account that is in
	// wheel or docker on the machine would not be in them in its own shell.
	Groups []int

	Home  string
	Shell string
}

// ListAccountsUser is the SSH username that asks which accounts a key opens,
// rather than asking for a session.
//
// A colon is the one character a unix account name can never contain — it is
// the field separator in the password file — so this can never collide with a
// real account, and no local account can be created to impersonate it.
//
// Answering it gives away nothing the caller could not already find out by
// trying each name in turn: the list is only ever the accounts this key opens.
const ListAccountsUser = "makima:accounts"

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
		PublicKeyCallback: func(meta ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) {
			perms, err := s.authorize(cfg, meta.User(), pub, remoteAddr(meta.RemoteAddr()))
			if err != nil {
				// One error for every rejection. A client learns whether a key
				// was accepted, which is unavoidable, and nothing else.
				return nil, errors.New("key not authorized")
			}
			authorizedKey = pub
			return perms, nil
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

	account := conn.Permissions.Extensions[accountExtension]
	listing := conn.Permissions.Extensions[listingExtension]
	grant := Grant{PTY: conn.Permissions.Extensions[ptyExtension] == "1"}

	for ch := range chans {
		if ch.ChannelType() != "session" {
			// Notably absent: direct-tcpip. Port forwarding through this
			// server would be a second, much broader hole than a shell, and
			// makima already forwards ports as a first-class thing that shows
			// up in status and obeys the mesh's access control.
			_ = ch.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		if listing != "" {
			go answerAccounts(ch, listing)
			continue
		}

		// Resolved again rather than carried from the handshake: an account
		// removed or locked in between should not still get a shell, and the
		// lookup is a password-database read.
		user, err := s.accountByName(cfg, account)
		if err != nil {
			_ = ch.Reject(ssh.Prohibited, "that account is no longer available")
			continue
		}
		go s.session(ch, cfg, user, grant)
	}
}

// The facts about a connection that outlive its handshake. ssh.Permissions is
// the only thing the library carries across, and it carries strings.
const (
	accountExtension = "makima-account"
	listingExtension = "makima-accounts"
	ptyExtension     = "makima-pty"
)

// authorize decides whether a key may log in under a username, and as what.
//
// The shape of the answer matters more than any single rule in it:
//
//	""  or the default account   the keys makima was configured with
//	another local account        that account's own authorized_keys
//	a name that is not local     the default account, as before there were any
//	                             others — a client sends the name of whoever is
//	                             sitting at it, which is rarely a name here
//	ListAccountsUser             no session at all, only the list
func (s *Server) authorize(cfg Config, name string, pub ssh.PublicKey, remote netip.Addr) (*ssh.Permissions, error) {
	if cfg.User == nil {
		return nil, errors.New("sshd: no account to run sessions as")
	}

	if name == ListAccountsUser {
		list := s.accountsFor(cfg, pub, remote)
		if len(list.Accounts) == 0 {
			return nil, errors.New("key opens no account here")
		}
		names := make([]string, 0, len(list.Accounts))
		for _, a := range list.Accounts {
			names = append(names, encodeAccount(a))
		}
		return &ssh.Permissions{Extensions: map[string]string{
			listingExtension: strings.Join(names, "\n"),
		}}, nil
	}

	// The default account, by name or by not naming one.
	wantsDefault := name == "" || name == cfg.User.Name
	if !wantsDefault && cfg.Accounts != nil {
		if _, err := cfg.Accounts.Lookup(name); err != nil {
			// Not an account here at all. The client is almost certainly
			// sending the username of whoever is sitting at the far machine,
			// which is what every ssh client does when nobody says otherwise.
			wantsDefault = true
		}
	} else if !wantsDefault && cfg.Accounts == nil {
		wantsDefault = true
	}

	if wantsDefault {
		grant, ok := defaultGrant(cfg, pub, remote)
		if !ok {
			return nil, errors.New("key not authorized")
		}
		return permissionsFor(cfg.User.Name, grant), nil
	}

	user, err := cfg.Accounts.Lookup(name)
	if err != nil {
		return nil, err
	}
	grant, ok := accountGrant(cfg, user, pub, remote)
	if !ok {
		return nil, errors.New("key not authorized")
	}
	return permissionsFor(user.Name, grant), nil
}

// defaultGrant asks the configured key set about the default account.
func defaultGrant(cfg Config, pub ssh.PublicKey, remote netip.Addr) (Grant, bool) {
	if cfg.Authorized == nil {
		return Grant{}, false
	}
	return cfg.Authorized(pub, remote)
}

// accountGrant asks one account's own authorized_keys about a key.
func accountGrant(cfg Config, u *SessionUser, pub ssh.PublicKey, remote netip.Addr) (Grant, bool) {
	if cfg.Accounts == nil || pub == nil {
		return Grant{}, false
	}
	keys, err := cfg.Accounts.Keys(u)
	if err != nil {
		return Grant{}, false
	}
	want := string(pub.Marshal())
	for _, k := range keys {
		if k.Key != nil && string(k.Key.Marshal()) == want && k.Allows(remote) {
			return Grant{PTY: k.PTY}, true
		}
	}
	return Grant{}, false
}

// accountsFor is every account this key opens on this machine.
func (s *Server) accountsFor(cfg Config, pub ssh.PublicKey, remote netip.Addr) AccountList {
	var out []Account
	if _, ok := defaultGrant(cfg, pub, remote); ok {
		out = append(out, Account{Name: cfg.User.Name, Default: true, Root: cfg.User.UID == 0})
	}
	if cfg.Accounts != nil {
		users, err := cfg.Accounts.List()
		if err != nil {
			s.log.Printf("ssh: could not list accounts: %v", err)
		}
		for _, u := range users {
			if u.Name == cfg.User.Name {
				continue
			}
			if _, ok := accountGrant(cfg, u, pub, remote); ok {
				out = append(out, Account{Name: u.Name, Root: u.UID == 0})
			}
		}
	}
	return AccountList{Accounts: SortAccounts(out)}
}

// accountByName resolves the account a session was authorized for.
func (s *Server) accountByName(cfg Config, name string) (*SessionUser, error) {
	if cfg.User != nil && (name == "" || name == cfg.User.Name) {
		return cfg.User, nil
	}
	if cfg.Accounts == nil {
		return nil, errors.New("sshd: no account source")
	}
	return cfg.Accounts.Lookup(name)
}

func permissionsFor(account string, g Grant) *ssh.Permissions {
	ext := map[string]string{accountExtension: account}
	if g.PTY {
		ext[ptyExtension] = "1"
	}
	return &ssh.Permissions{Extensions: ext}
}

// remoteAddr pulls the address out of whatever net.Addr the connection has.
func remoteAddr(a net.Addr) netip.Addr {
	if t, ok := a.(*net.TCPAddr); ok {
		if addr, ok := netip.AddrFromSlice(t.IP); ok {
			return addr.Unmap()
		}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// atomic64 is a counter touched from every connection's own goroutine, which
// is why it is atomic rather than guarded: handle runs outside the server's
// mutex, and the comment here used to claim otherwise.
type atomic64 struct{ n atomic.Uint64 }

func (a *atomic64) inc()        { a.n.Add(1) }
func (a *atomic64) get() uint64 { return a.n.Load() }
