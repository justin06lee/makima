package tor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Key is an onion service's identity: an ed25519 seed.
//
// The onion address is derived from the public half, so the address lasts
// exactly as long as the key does. That is the whole reason it is kept: every
// node is told the address once, and a server that made a new key on each
// start would be a new address nobody had heard of.
type Key struct {
	seed [ed25519.SeedSize]byte
}

// NewKey makes a fresh onion identity.
func NewKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k.seed[:]); err != nil {
		return Key{}, fmt.Errorf("generate onion key: %w", err)
	}
	return k, nil
}

// KeyFromSeed is the onion identity a seed makes. For a key two machines
// derive from a secret they share, rather than one either of them draws.
func KeyFromSeed(seed [ed25519.SeedSize]byte) Key { return Key{seed: seed} }

// Public is the ed25519 public key the address is made from.
func (k Key) Public() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(k.seed[:]).Public().(ed25519.PublicKey)
}

// Host is the onion address, "<56 letters>.onion".
func (k Key) Host() string { return hostOf(k.Public()) }

// IsZero reports whether k was never set.
func (k Key) IsZero() bool { return k.seed == [ed25519.SeedSize]byte{} }

// blob is the key as ADD_ONION takes it.
//
// Tor wants the expanded form, not the seed: SHA-512 of the seed with the
// scalar half clamped, which is what ed25519 signing does internally and what
// Tor keeps in hs_ed25519_secret_key. Handing it over this way means the key
// lives only in makima's state; Tor holds it in memory and writes nothing.
func (k Key) blob() string {
	h := sha512.Sum512(k.seed[:])
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return "ED25519-V3:" + base64.StdEncoding.EncodeToString(h[:])
}

// onionVersion is the address format, v3: the only one Tor still serves.
const onionVersion = 3

// hostOf is the v3 onion address of an ed25519 public key: the key, a
// two-byte checksum and the version byte, in lower-case base32.
func hostOf(pub ed25519.PublicKey) string {
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pub)
	h.Write([]byte{onionVersion})
	sum := h.Sum(nil)

	b := make([]byte, 0, ed25519.PublicKeySize+3)
	b = append(b, pub...)
	b = append(b, sum[:2]...)
	b = append(b, onionVersion)
	return strings.ToLower(base32.StdEncoding.EncodeToString(b)) + ".onion"
}

// IsOnion reports whether host — a name, or a host:port — is an onion address.
func IsOnion(host string) bool {
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}
	return strings.HasSuffix(strings.ToLower(strings.TrimSuffix(host, ".")), ".onion")
}

// keyFile is the key on disk.
type keyFile struct {
	Seed []byte `json:"ed25519_seed"`
}

// LoadKey reads an onion identity, generating one on first run.
func LoadKey(path string) (Key, error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var f keyFile
		if err := json.Unmarshal(b, &f); err != nil {
			return Key{}, fmt.Errorf("parse %s: %w", path, err)
		}
		if len(f.Seed) != ed25519.SeedSize {
			return Key{}, fmt.Errorf("%s: no onion key", path)
		}
		var k Key
		copy(k.seed[:], f.Seed)
		return k, nil

	case errors.Is(err, os.ErrNotExist):
		k, err := NewKey()
		if err != nil {
			return Key{}, err
		}
		if err := saveKey(path, k); err != nil {
			return Key{}, err
		}
		return k, nil

	default:
		return Key{}, fmt.Errorf("read %s: %w", path, err)
	}
}

// saveKey writes an onion identity: mode 0600, write-then-rename, as every
// other key file in makima — a torn write is a new address on the next start.
func saveKey(path string, k Key) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create onion key dir: %w", err)
	}
	b, err := json.MarshalIndent(keyFile{Seed: k.seed[:]}, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".makima-onion-*")
	if err != nil {
		return fmt.Errorf("create temp onion key: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// OnionHost is the onion address of an ed25519 public key.
func OnionHost(pub ed25519.PublicKey) string { return hostOf(pub) }

// ParseOnion reads an onion address back into the public key it was made
// from, refusing one whose checksum or version is wrong — a mistyped address
// fails here rather than as a minute of tor failing to find it.
func ParseOnion(host string) (ed25519.PublicKey, error) {
	label := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(host), "."), ".onion")
	b, err := base32.StdEncoding.DecodeString(strings.ToUpper(label))
	if err != nil || len(b) != ed25519.PublicKeySize+3 {
		return nil, fmt.Errorf("%q is not an onion address", host)
	}
	pub := ed25519.PublicKey(b[:ed25519.PublicKeySize])
	if b[len(b)-1] != onionVersion || hostOf(pub) != label+".onion" {
		return nil, fmt.Errorf("%q is not a valid onion address — a character is wrong", host)
	}
	return pub, nil
}
