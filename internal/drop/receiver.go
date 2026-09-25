package drop

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Receiver accepts files onto this machine.
//
// It binds the node's mesh address and nothing else, so it exists only for
// peers and cannot be reached from the LAN, from localhost, or from the
// internet. That is the same choice internal/serve makes for published ports,
// and for the same reason: the mesh is the authorisation boundary, so being on
// it should be the only way in.
type Receiver struct {
	log *log.Logger

	// applyMu makes Apply and Close one at a time. Apply lets go of mu
	// while it closes, creates and listens, and two of them interleaved —
	// the poll loop, the port scanner and the local API all call it — left
	// the receiver writing into one directory while reporting another.
	applyMu sync.Mutex

	mu      sync.Mutex
	ln      net.Listener
	addr    netip.Addr
	dir     string
	maxSize int64
	owner   *Owner

	// root is the inbox directory itself, opened once: files are created
	// inside it, never by path, so nothing done to the path afterwards — a
	// symlink put in its place — can redirect where they are written.
	root *os.Root

	// received counts completed transfers, for status.
	received uint64
}

// Owner is the user new files should belong to.
//
// The daemon runs as root because it holds a TUN device. Files it creates
// would therefore be root-owned in somebody's home directory, where they could
// not be deleted without sudo — a small thing that makes the feature feel
// broken. Nil means leave ownership alone, which is right when the inbox is
// somewhere the daemon owns anyway.
type Owner struct {
	UID int
	GID int

	// Home is a directory the owner controls and the inbox lives under — in
	// their home, usually. Everything the daemon does on the way to the
	// inbox stays inside it: the daemon is root, the directories are the
	// owner's, and root following a symlink the owner put there would hand
	// the owner whatever it points at. Empty when the inbox is somewhere
	// the owner does not control.
	Home string
}

// New builds a receiver. It does not listen until Apply.
func New(logger *log.Logger) *Receiver {
	if logger == nil {
		logger = log.Default()
	}
	return &Receiver{log: logger, maxSize: DefaultMaxSize}
}

// Config is everything that can change about a receiver while it runs.
type Config struct {
	// Dir is where files land. Empty turns receiving off entirely, which is
	// what -no-recv sets.
	Dir string

	// MaxSize caps one file. Zero means DefaultMaxSize.
	MaxSize int64

	// Owner is who new files belong to, or nil to leave them to the daemon.
	Owner *Owner
}

// Apply binds the receiver to an address and a directory, replacing whatever
// it was doing before.
//
// Idempotent: called on every netmap and every settings change, and does
// nothing when nothing has changed. Rebinding is not free — it drops
// in-flight transfers — so it happens only when the address or the directory
// genuinely differs.
func (r *Receiver) Apply(addr netip.Addr, cfg Config) {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()

	r.mu.Lock()

	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	r.maxSize = maxSize
	r.owner = cfg.Owner

	unchanged := r.ln != nil && r.addr == addr && r.dir == cfg.Dir
	if unchanged {
		r.mu.Unlock()
		return
	}

	old, oldRoot := r.ln, r.root
	r.ln = nil
	r.root = nil
	r.addr = addr
	r.dir = cfg.Dir
	r.mu.Unlock()

	if old != nil {
		old.Close()
	}
	if oldRoot != nil {
		oldRoot.Close()
	}
	if cfg.Dir == "" || !addr.IsValid() {
		return
	}

	root, err := openInbox(cfg.Dir, cfg.Owner)
	if err != nil {
		r.log.Printf("inbox %s: %v", cfg.Dir, err)
		return
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(addr.String(), fmt.Sprint(Port)))
	if err != nil {
		root.Close()
		r.log.Printf("inbox: %v", err)
		return
	}

	r.mu.Lock()
	r.ln = ln
	r.root = root
	r.mu.Unlock()

	r.log.Printf("inbox %s — peers can send files here", cfg.Dir)
	go r.accept(ln)
}

// Close stops receiving.
func (r *Receiver) Close() {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()

	r.mu.Lock()
	ln, root := r.ln, r.root
	r.ln = nil
	r.root = nil
	r.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
	if root != nil {
		root.Close()
	}
}

// openInbox makes sure the inbox exists and opens it.
//
// For an inbox under an owner's home, every step is taken inside that home
// (os.Root), so a symlink anywhere on the way that points out of it is
// refused rather than followed. Root used to MkdirAll and then Chown the
// path, following whatever the owner had put there: a symlink from
// ~/Downloads/makima to /etc handed the owner /etc, and had files from peers
// written into it. Only directories created here are given to the owner,
// and the inbox itself with Lchown, which never follows a link.
func openInbox(dir string, o *Owner) (*os.Root, error) {
	if o == nil || o.Home == "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		return os.OpenRoot(dir)
	}

	rel, err := filepath.Rel(o.Home, dir)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("%s is not inside %s", dir, o.Home)
	}
	home, err := os.OpenRoot(o.Home)
	if err != nil {
		return nil, err
	}
	defer home.Close()

	root, err := inboxWithin(home, rel, o)
	if err == nil {
		return root, nil
	}
	// A link out of the home — a Downloads folder kept on another disk — is
	// followed only to a directory the owner owns: root writing there is no
	// more than the owner could do. A link to /etc is not.
	if linked, lerr := inboxLinkedOut(dir, o); lerr == nil {
		return linked, nil
	}
	return nil, err
}

// inboxWithin makes and opens the inbox without leaving the home.
func inboxWithin(home *os.Root, rel string, o *Owner) (*os.Root, error) {
	cur := ""
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		switch err := home.Mkdir(cur, 0o700); {
		case err == nil:
			// Best effort: an inbox the daemon cannot give away still works,
			// it is just inconvenient, and refusing to receive would be worse.
			_ = home.Lchown(cur, o.UID, o.GID)
		case errors.Is(err, fs.ErrExist):
		default:
			return nil, err
		}
	}
	_ = home.Lchown(rel, o.UID, o.GID)
	return home.OpenRoot(rel)
}

// inboxLinkedOut opens an inbox whose parent is reached through a link out
// of the home, provided the directories actually opened belong to the owner.
// Ownership is read from the open directory itself, not from its path, so
// the link cannot be pointed elsewhere between the check and the use.
func inboxLinkedOut(dir string, o *Owner) (*os.Root, error) {
	parent, err := os.OpenRoot(filepath.Dir(dir))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if !ownedByOwner(parent, o) {
		return nil, fmt.Errorf("%s leads to a directory %s does not own", filepath.Dir(dir), o.homeName())
	}
	base := filepath.Base(dir)
	if err := parent.Mkdir(base, 0o700); err == nil {
		_ = parent.Lchown(base, o.UID, o.GID)
	} else if !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	root, err := parent.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	if !ownedByOwner(root, o) {
		root.Close()
		return nil, fmt.Errorf("%s is not %s's", dir, o.homeName())
	}
	return root, nil
}

// ownedByOwner reports whether an opened directory belongs to the owner.
func ownedByOwner(r *os.Root, o *Owner) bool {
	fi, err := r.Stat(".")
	if err != nil {
		return false
	}
	uid, ok := fileUID(fi)
	return ok && uid == o.UID
}

func (o *Owner) homeName() string { return "the owner of " + o.Home }

// Status reports where files land and how many have arrived.
func (r *Receiver) Status() (dir string, active bool, received uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dir, r.ln != nil, r.received
}

func (r *Receiver) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			// A closed listener is Apply or Close doing their job.
			return
		}
		go r.handle(c)
	}
}

func (r *Receiver) handle(c net.Conn) {
	defer c.Close()

	res, err := r.receive(c)
	if err != nil {
		r.log.Printf("inbox: %v", err)
		res = Result{Error: err.Error()}
	}

	_ = c.SetWriteDeadline(time.Now().Add(idleTimeout))
	_ = writeFrame(c, res)
}

func (r *Receiver) receive(c net.Conn) (Result, error) {
	r.mu.Lock()
	dir, maxSize, owner, root := r.dir, r.maxSize, r.owner, r.root
	r.mu.Unlock()

	if dir == "" || root == nil {
		return Result{}, errors.New("this machine is not accepting files")
	}

	// One idle deadline for the whole connection, pushed forward on every
	// read that made progress. The header and the body are the same rule: a
	// peer gets as long as it likes provided it is doing something.
	in := newIdleReader(c, idleTimeout)

	var hello [len(magic) + 1]byte
	if _, err := io.ReadFull(in, hello[:]); err != nil {
		return Result{}, fmt.Errorf("read greeting: %w", err)
	}
	if [len(magic)]byte(hello[:len(magic)]) != magic {
		return Result{}, errors.New("that is not a makima transfer")
	}
	if hello[len(magic)] != ProtocolVersion {
		return Result{}, fmt.Errorf("sender speaks transfer version %d, this machine speaks %d", hello[len(magic)], ProtocolVersion)
	}

	var h Header
	if err := readFrame(in, &h); err != nil {
		return Result{}, fmt.Errorf("read header: %w", err)
	}

	name, err := SafeName(h.Name)
	if err != nil {
		return Result{}, err
	}
	if h.Size < 0 {
		return Result{}, errors.New("drop: negative file size")
	}
	if h.Size > maxSize {
		// Refused before anything is created, so an oversized transfer never
		// becomes a partial file somebody has to clean up.
		return Result{}, fmt.Errorf("%s is %s, over this machine's %s limit", name, humanSize(h.Size), humanSize(maxSize))
	}

	f, created, err := createUnique(root, name, fileMode(h.Mode))
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	path := filepath.Join(dir, created)

	if owner != nil {
		_ = f.Chown(owner.UID, owner.GID)
	}

	// Bounded by the size that was declared, so a sender that keeps writing
	// past it is cut off rather than allowed to fill the disk with a file it
	// said was small. Bounded in time only by going quiet.
	n, err := io.Copy(f, io.LimitReader(in, h.Size))
	if err != nil {
		root.Remove(created)
		return Result{}, fmt.Errorf("receive %s: %w", name, err)
	}
	if n != h.Size {
		// A short transfer is a truncated file, and keeping it would be worse
		// than losing it: it looks complete.
		root.Remove(created)
		return Result{}, fmt.Errorf("%s arrived incomplete: %d of %d bytes", name, n, h.Size)
	}
	if err := f.Sync(); err != nil {
		return Result{}, fmt.Errorf("write %s: %w", path, err)
	}

	r.mu.Lock()
	r.received++
	r.mu.Unlock()

	from := h.From
	if from == "" {
		from = "a peer"
	}
	r.log.Printf("received %s (%s) from %s", filepath.Base(path), humanSize(n), from)

	return Result{OK: true, Path: path}, nil
}

// fileMode is the permission a received file is created with.
//
// 0600 always, plus the executable bit if the sender had one. A sender does
// not get to widen permissions on somebody else's machine — the most a file
// arriving from the network should be is readable by the person who received
// it — but silently losing the executable bit on a script is a real annoyance.
func fileMode(mode uint32) os.FileMode {
	m := os.FileMode(0o600)
	if mode&0o111 != 0 {
		m |= 0o100
	}
	return m
}

// humanSize renders a byte count the way a person would say it.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for size := n / unit; size >= unit; size /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
