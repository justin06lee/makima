package sshd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Where a machine's authorized keys come from.
//
// A file is the obvious source and the one everybody already has. The GitHub
// source exists because the alternative — "copy your public key across, which
// means getting a shell on the machine you are trying to get a shell on" — is
// the chicken-and-egg that makes a fresh machine annoying, and because the
// keys are already published: github.com/<user>.keys is a public endpoint
// returning exactly the keys that account can push with.
//
// It is a convenience with a real consequence, so it is stated plainly rather
// than buried: naming an account here means whoever controls that account can
// get a shell on this machine. That is the same trust as writing their key
// into authorized_keys, except it stays true if the account is later
// compromised or its keys are rotated by somebody else.

// Source is one place to read authorized keys from.
//
// Written as a string because that is how it is typed and stored:
// "/home/you/.ssh/authorized_keys" or "github:justin06lee".
type Source string

// githubPrefix marks a source as a GitHub account.
const githubPrefix = "github:"

// refreshInterval is how often a remote source is re-read.
//
// Hourly. Keys change rarely, a fetch is one small request, and an hour is
// short enough that revoking a key on GitHub takes effect on the same day
// somebody thinks to do it.
const refreshInterval = time.Hour

// fetchTimeout bounds one remote read. Short: a source that is slow is a
// source that is down, and the last good set is still in memory.
const fetchTimeout = 15 * time.Second

// Keys is a live set of authorized keys, refreshed in the background.
//
// The set is swapped atomically and never emptied by a failure. A machine
// whose keys came from GitHub must not lock everybody out because the network
// dropped — the last known-good set stays in force, which is the same thing an
// unreadable authorized_keys file already does.
type Keys struct {
	log *log.Logger

	mu      sync.RWMutex
	sources []Source
	keys    map[string]bool
	updated time.Time
	lastErr error

	cancel context.CancelFunc
	once   sync.Once
}

// NewKeys builds an empty set.
func NewKeys(logger *log.Logger) *Keys {
	if logger == nil {
		logger = log.Default()
	}
	return &Keys{log: logger, keys: map[string]bool{}}
}

// Set replaces the sources and reads them once, synchronously.
//
// Synchronous on purpose: switching the server on and having it accept nobody
// for a second afterwards looks exactly like a broken key, and the person who
// just typed the command is watching.
func (k *Keys) Set(ctx context.Context, sources []Source) error {
	k.mu.Lock()
	k.sources = append([]Source(nil), sources...)
	k.mu.Unlock()

	err := k.refresh(ctx)

	// One refresher for the life of the process, started on first use.
	k.once.Do(func() {
		bg, cancel := context.WithCancel(context.Background())
		k.cancel = cancel
		go k.loop(bg)
	})
	return err
}

// Close stops refreshing.
func (k *Keys) Close() {
	if k.cancel != nil {
		k.cancel()
	}
}

// Allow reports whether a key is authorized. Safe for concurrent use, and on
// the authentication path for every connection.
func (k *Keys) Allow(pub ssh.PublicKey) bool {
	if pub == nil {
		return false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keys[string(pub.Marshal())]
}

// Status reports how many keys are in force, when they were last read, and
// what went wrong if anything did.
func (k *Keys) Status() (count int, updated time.Time, err error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.keys), k.updated, k.lastErr
}

func (k *Keys) loop(ctx context.Context) {
	t := time.NewTicker(refreshInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = k.refresh(ctx)
		}
	}
}

// refresh re-reads every source.
//
// A source that fails is reported but does not empty the set: partial results
// are kept, because losing access to a machine is worse than briefly honouring
// a key that was meant to be revoked, and the alternative has no recovery path
// that does not involve physical access.
func (k *Keys) refresh(ctx context.Context) error {
	k.mu.RLock()
	sources := append([]Source(nil), k.sources...)
	k.mu.RUnlock()

	next := make(map[string]bool)
	var failures []string

	for _, s := range sources {
		keys, err := s.read(ctx)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", s, err))
			continue
		}
		for _, key := range keys {
			next[string(key.Marshal())] = true
		}
	}

	var err error
	if len(failures) > 0 {
		err = errors.New(strings.Join(failures, "; "))
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	if len(next) == 0 && err != nil && len(k.keys) > 0 {
		// Everything failed and we already had keys. Keep them.
		k.lastErr = err
		k.log.Printf("ssh: could not refresh authorized keys (%v); keeping the %d already in force", err, len(k.keys))
		return err
	}

	k.keys = next
	k.updated = time.Now()
	k.lastErr = err
	return err
}

// read fetches the keys one source names.
func (s Source) read(ctx context.Context) ([]ssh.PublicKey, error) {
	str := string(s)
	if account, ok := strings.CutPrefix(str, githubPrefix); ok {
		return fetchGitHub(ctx, account)
	}
	b, err := os.ReadFile(str)
	if err != nil {
		return nil, err
	}
	return ParseAuthorizedKeys(b)
}

// ParseAuthorizedKeys reads an authorized_keys file.
//
// Tolerant of what such files actually contain: comments, blank lines, and
// option prefixes. A line that does not parse is skipped rather than failing
// the file, because one stale entry must not lock out every other key in it.
func ParseAuthorizedKeys(b []byte) ([]ssh.PublicKey, error) {
	var out []ssh.PublicKey

	for len(b) > 0 {
		key, _, _, rest, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			// Skip to the next line and carry on.
			if i := bytes.IndexByte(b, '\n'); i >= 0 {
				b = b[i+1:]
				continue
			}
			break
		}
		out = append(out, key)
		b = rest
	}

	if len(out) == 0 {
		return nil, errors.New("no usable public keys")
	}
	return out, nil
}

// maxKeyBody caps a remote response. A key list is a few hundred bytes; this
// is generous enough never to matter and small enough that a hostile or broken
// endpoint cannot make the daemon allocate.
const maxKeyBody = 1 << 20

// fetchGitHub reads an account's published SSH keys.
func fetchGitHub(ctx context.Context, account string) ([]ssh.PublicKey, error) {
	if !validAccount(account) {
		return nil, fmt.Errorf("%q is not a GitHub account name", account)
	}

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	url := "https://github.com/" + account + ".keys"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github returned %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeyBody))
	if err != nil {
		return nil, err
	}

	keys, err := ParseAuthorizedKeys(body)
	if err != nil {
		return nil, fmt.Errorf("%s has no public keys on GitHub", account)
	}
	return keys, nil
}

// validAccount checks a name before it becomes part of a URL.
//
// GitHub's own rule: alphanumerics and hyphens, not starting or ending with
// one, up to 39 characters. Enforced here so a name containing a slash or a
// dot cannot turn a fetch into a request for something else entirely.
func validAccount(s string) bool {
	if s == "" || len(s) > 39 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}
