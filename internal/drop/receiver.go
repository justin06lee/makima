package drop

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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

	mu      sync.Mutex
	ln      net.Listener
	addr    netip.Addr
	dir     string
	maxSize int64
	owner   *Owner

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

	old := r.ln
	r.ln = nil
	r.addr = addr
	r.dir = cfg.Dir
	r.mu.Unlock()

	if old != nil {
		old.Close()
	}
	if cfg.Dir == "" || !addr.IsValid() {
		return
	}

	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		r.log.Printf("inbox %s: %v", cfg.Dir, err)
		return
	}
	if o := cfg.Owner; o != nil {
		// Best effort: an inbox the daemon cannot chown still works, it is
		// just inconvenient, and refusing to receive over it would be worse.
		_ = os.Chown(cfg.Dir, o.UID, o.GID)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(addr.String(), fmt.Sprint(Port)))
	if err != nil {
		r.log.Printf("inbox: %v", err)
		return
	}

	r.mu.Lock()
	r.ln = ln
	r.mu.Unlock()

	r.log.Printf("inbox %s — peers can send files here", cfg.Dir)
	go r.accept(ln)
}

// Close stops receiving.
func (r *Receiver) Close() {
	r.mu.Lock()
	ln := r.ln
	r.ln = nil
	r.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
}

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
	dir, maxSize, owner := r.dir, r.maxSize, r.owner
	r.mu.Unlock()

	if dir == "" {
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

	path, err := UniqueName(dir, name)
	if err != nil {
		return Result{}, err
	}

	// O_EXCL because UniqueName's answer is a moment old, and the gap between
	// looking and creating is exactly where a second transfer of the same name
	// would land. Failing here is correct: it means the name was taken after
	// all.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode(h.Mode))
	if err != nil {
		return Result{}, fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	if owner != nil {
		_ = f.Chown(owner.UID, owner.GID)
	}

	// Bounded by the size that was declared, so a sender that keeps writing
	// past it is cut off rather than allowed to fill the disk with a file it
	// said was small. Bounded in time only by going quiet.
	n, err := io.Copy(f, io.LimitReader(in, h.Size))
	if err != nil {
		os.Remove(path)
		return Result{}, fmt.Errorf("receive %s: %w", name, err)
	}
	if n != h.Size {
		// A short transfer is a truncated file, and keeping it would be worse
		// than losing it: it looks complete.
		os.Remove(path)
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
