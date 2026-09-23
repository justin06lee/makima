// Package conf loads and saves a node's on-disk identity.
//
// A node runs in one of three modes and the file says which:
//
//	static      no LoginServer, not Serverless. The peer list in this file is
//	            the whole mesh, maintained by hand. It stays supported because
//	            it needs no infrastructure at all — and because it is the only
//	            mode where WireGuard gets an ordinary UDP socket.
//	serverless  no LoginServer, Serverless set. The peer list is maintained by
//	            pairing: two machines exchange one pasted address and each
//	            writes the other in. No server, but a real path-selecting
//	            socket, because pairing and NAT traversal both need one.
//	managed     LoginServer set. The peer list here is only a cache of the last
//	            netmap the control server sent, so a node that boots while the
//	            server is unreachable still comes up with the mesh it last knew.
package conf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/serve"
)

// DefaultPath is where the daemon looks when no path is given. The daemon
// needs root to create a TUN device anyway, so a root-owned location costs
// nothing and keeps the private keys out of a user-writable directory.
const DefaultPath = "/etc/makima/node.json"

// SchemaVersion is what this build of makima writes.
//
// It exists so that a config written by a later version is recognisable as one,
// and so a config written by an earlier one can be brought forward rather than
// thrown away. An upgrade must never be a reason to lose a network: the file
// holds this machine's identity on the mesh, and regenerating it means being
// re-admitted by hand on the machine that holds the network.
const SchemaVersion = 1

// File is a node's complete on-disk state.
type File struct {
	// Version is the schema this file was written by. Absent means a config
	// from before there were versions, which is read the same way.
	Version int `json:"version,omitempty"`

	// NodeKey is the WireGuard key. Rotatable: changing it and
	// re-registering is a normal operation, which is why the control plane
	// keys identity off MachineKey instead.
	NodeKey key.Private `json:"node_key"`

	// MachineKey is this device's permanent identity to the control server,
	// and the key its control channel is sealed under.
	MachineKey key.Private `json:"machine_key"`

	// DiscoKey authenticates NAT-traversal probes, so path discovery can run
	// before any WireGuard session exists.
	DiscoKey key.Private `json:"disco_key"`

	ListenPort uint16 `json:"listen_port"`

	// LoginServer empty means no control plane: static or serverless.
	LoginServer string     `json:"login_server,omitempty"`
	ServerKey   key.Public `json:"server_key,omitzero"`

	// ControlURLs are the control plane's other addresses, as it last named
	// them — kept so a node that starts somewhere its LoginServer cannot be
	// reached still knows where else to look.
	ControlURLs []string `json:"control_urls,omitempty"`

	// Serverless marks a node that gains peers by pairing rather than by
	// registering with a control plane.
	//
	// It exists as a flag rather than being inferred from the peer list
	// because it has to be true *before* there are any peers: a machine
	// running `makima pair` for the first time has nobody, and still needs the
	// path-selecting socket in order to be knocked on at all.
	Serverless bool `json:"serverless,omitempty"`

	// AuthKey is a join credential held only between `makima join` and the
	// daemon's first successful registration, then cleared. It exists because
	// a node that is expired by an operator has to present one again, and
	// prompting for it on a headless machine is not an option.
	AuthKey string `json:"auth_key,omitempty"`

	// AdvertiseRoutes and AdvertiseExit are this node's standing offers to
	// route for the mesh. Requests, not facts: nothing takes effect until the
	// control plane says it was approved.
	AdvertiseRoutes []netip.Prefix `json:"advertise_routes,omitempty"`
	AdvertiseExit   bool           `json:"advertise_exit,omitempty"`

	// ExitNode is the peer this node routes its own traffic through, by name.
	// Empty means normal routing.
	ExitNode string `json:"exit_node,omitempty"`

	// Services are the local ports this node publishes on its mesh address.
	//
	// The target half stays here and is never sent anywhere. The control plane
	// learns only which mesh port is open, because that is all any other node
	// needs and telling it more would publish this machine's internal layout.
	Services []serve.Service `json:"services,omitempty"`

	// DeniedPorts are ports this node must never publish, even when something
	// is listening on them.
	//
	// Needed because loopback services are published automatically: without a
	// record of the refusal, withdrawing one would last until the next scan
	// noticed it again five seconds later. This is what makes "deny" mean
	// "keep it off the mesh" rather than "take it off the mesh for a moment".
	DeniedPorts []uint16 `json:"denied_ports,omitempty"`

	// Owner is the local account this machine's makima belongs to: whose
	// desktop socket is opened, whose Downloads receive files, and which
	// account a shell session runs as by default.
	//
	// Written down because every other way of learning it is a property of
	// whichever process happened to start the daemon. SUDO_USER exists only
	// under sudo; the console user exists only while somebody is logged in at
	// the screen. A machine set up over SSH as root has neither, and one
	// started by launchd at boot has neither either — so without this, the
	// read-only socket that the desktop app and every non-root tool read is
	// never opened at all, and nothing says why.
	Owner string `json:"owner,omitempty"`

	// Inbox is where files sent by peers land, and InboxOff switches
	// receiving off entirely.
	//
	// Two fields rather than one, because "" has to keep meaning "the
	// default" — a node whose inbox is off and one that has never been
	// configured are different states, and collapsing them would make
	// `makima inbox -off` indistinguishable from a fresh install.
	Inbox    string `json:"inbox,omitempty"`
	InboxOff bool   `json:"inbox_off,omitempty"`

	// SSH switches on the built-in SSH server, SSHKeys names where its
	// authorized keys come from, and SSHUser is the account a session runs as
	// when the client asks for no other.
	//
	// Off unless explicitly set. Everything else makima does is reversible by
	// stopping the daemon; a shell server is the one feature where being on by
	// default would be a decision made on somebody's behalf that they might
	// not discover for months.
	SSH     bool     `json:"ssh,omitempty"`
	SSHKeys []string `json:"ssh_keys,omitempty"`
	SSHUser string   `json:"ssh_user,omitempty"`

	// Domain and HomeRelay cache what the last netmap said, so a node that
	// starts while the control server is unreachable still comes up with mesh
	// DNS and a relay rather than isolated.
	Domain    string       `json:"domain,omitempty"`
	HomeRelay netmap.Relay `json:"home_relay,omitzero"`

	Self  netmap.Node   `json:"self"`
	Peers []netmap.Node `json:"peers,omitempty"`

	// extra is every field in the file this build does not know about, kept so
	// that saving does not delete it.
	//
	// The daemon rewrites this file on every netmap update. Without this, going
	// back one version — or running an older makima against a newer config for
	// a minute — would quietly strip whatever the newer one had put there, and
	// the loss would only be noticed on the way forward again.
	extra map[string]json.RawMessage

	// upgradedFrom is the version this file was on disk, when that was older
	// than SchemaVersion. Zero once it has been dealt with.
	upgradedFrom int
	wasUpgraded  bool
}

// Upgraded reports whether Load brought this file forward, and from which
// version. The caller decides what to do about it — the daemon backs the old
// one up and says so; a read-only command just uses the result.
func (f *File) Upgraded() (from int, yes bool) { return f.upgradedFrom, f.wasUpgraded }

// NewIdentity generates a node's three keypairs.
func NewIdentity() (nodeKey, machineKey, discoKey key.Private, err error) {
	if nodeKey, err = key.NewPrivate(); err != nil {
		return
	}
	if machineKey, err = key.NewPrivate(); err != nil {
		return
	}
	discoKey, err = key.NewPrivate()
	return
}

// Managed reports whether a control server owns this node's peer list.
func (f *File) Managed() bool { return f.LoginServer != "" }

// NeedsPathSelection reports whether this node should be given magicsock
// rather than an ordinary UDP socket.
//
// The distinction is not cosmetic. magicsock attributes an inbound packet to a
// peer by address or by relay header, and it can only do that where disco keys
// exist to establish either. A hand-maintained static mesh has none, so giving
// it the path-selecting socket would break the documented behaviour that
// whichever machine speaks first teaches the other where it lives.
//
// A serverless node is the opposite case: pairing *is* a disco exchange, and a
// relay is often the only place two machines behind NAT can meet, so it needs
// the selecting socket from the moment it starts — before it has any peers to
// infer that from.
func (f *File) NeedsPathSelection() bool { return f.Managed() || f.Serverless }

// PairedPeer returns the peer with a given node key, and whether it exists.
func (f *File) PairedPeer(k key.Public) (netmap.Node, bool) {
	for _, p := range f.Peers {
		if p.Key == k {
			return p, true
		}
	}
	return netmap.Node{}, false
}

// AdvertisedServices renders the local service list into the form the control
// plane is told about: which mesh ports are open, and nothing else.
func (f *File) AdvertisedServices() []netmap.Service {
	if len(f.Services) == 0 {
		return nil
	}
	out := make([]netmap.Service, 0, len(f.Services))
	for _, s := range f.Services {
		out = append(out, netmap.Service{
			Name:   s.Name,
			Port:   s.Port,
			Scheme: netmap.GuessScheme(s.Port),
		})
	}
	return out
}

// NetMap renders the file into the mesh view the daemon consumes.
func (f *File) NetMap() *netmap.NetMap {
	return &netmap.NetMap{
		PrivateKey: f.NodeKey,
		ListenPort: f.ListenPort,
		Self:       f.Self,
		Peers:      f.Peers,
		HomeRelay:  f.HomeRelay,
		Domain:     f.Domain,
	}
}

// encode renders the file, carrying through any fields this build does not
// know about.
func (f *File) encode() ([]byte, error) {
	// Stamped on the way out rather than on the way in, so a file built in
	// memory by `makima init` or `makima join` carries a version from its very
	// first write and is never mistaken for one that predates them.
	if f.Version == 0 {
		f.Version = SchemaVersion
	}

	b, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	if len(f.extra) == 0 {
		var indented bytes.Buffer
		if err := json.Indent(&indented, b, "", "  "); err != nil {
			return nil, fmt.Errorf("encode config: %w", err)
		}
		return append(indented.Bytes(), '\n'), nil
	}

	var merged map[string]json.RawMessage
	if err := json.Unmarshal(b, &merged); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	for k, v := range f.extra {
		// Known fields win: one that is absent because it is empty is absent
		// on purpose, and putting the old value back would undo clearing it.
		if _, ours := merged[k]; !ours {
			merged[k] = v
		}
	}
	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return append(out, '\n'), nil
}

// Load reads a node configuration, bringing an older one forward.
//
// Best effort, and deliberately generous about what it accepts. A config is
// not something somebody can be asked to produce again: it is this machine's
// identity on a mesh, and the machine that could re-admit it may be the one
// that is unreachable. So anything that can be filled in is filled in, and
// only the things that cannot be — a missing node key, a static node with no
// address — are refused.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// Everything in the file, so fields this build does not know survive being
	// rewritten by it.
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	f.extra = unknownFields(raw)

	if err := f.upgrade(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	if f.NodeKey.IsZero() {
		return nil, fmt.Errorf("%s: no node key; run 'makima init' or 'makima join' first", path)
	}
	// A managed node legitimately has no address until its first successful
	// registration, so only static mode can demand one up front.
	if !f.Managed() && len(f.Self.Addresses) == 0 {
		return nil, fmt.Errorf("%s: node has no mesh address", path)
	}
	return &f, nil
}

// upgrade fills in what a newer makima expects and an older one never wrote.
//
// Each step is idempotent and none of them touches a key that is already
// there, so running this against an already-current file changes nothing —
// which is what makes it safe to run on every single load.
func (f *File) upgrade() error {
	was := f.Version
	if was < SchemaVersion {
		f.upgradedFrom, f.wasUpgraded = was, true
	}

	// v0 → v1: the disco key and the machine key were added after the first
	// configs were written. Both are this node's own secrets, so generating a
	// missing one costs nothing but a re-registration.
	if f.DiscoKey.IsZero() {
		k, err := key.NewPrivate()
		if err != nil {
			return fmt.Errorf("generate a disco key: %w", err)
		}
		f.DiscoKey = k
		f.wasUpgraded = true
	}
	if f.MachineKey.IsZero() {
		if f.Managed() {
			// A managed node's machine key *is* its identity to the control
			// plane. Inventing one would silently make this a different
			// machine, so this one has to be said out loud.
			return errors.New("no machine key, and this node belongs to a control plane — rejoin it with 'makima join'")
		}
		k, err := key.NewPrivate()
		if err != nil {
			return fmt.Errorf("generate a machine key: %w", err)
		}
		f.MachineKey = k
		f.wasUpgraded = true
	}

	// A version from the future is left as it was found. Writing our own over
	// it would claim this build understands the file, and the unknown fields
	// kept above are the other half of not making that claim.
	if f.Version < SchemaVersion {
		f.Version = SchemaVersion
	}
	return nil
}

// unknownFields is everything in the file with no field to hold it.
func unknownFields(raw map[string]json.RawMessage) map[string]json.RawMessage {
	known := knownFields()
	out := map[string]json.RawMessage{}
	for k, v := range raw {
		if !known[k] {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// knownFields is every JSON name File has, by reflection, so adding a field
// never means remembering to add it to a second list here as well.
func knownFields() map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeFor[File]()
	for i := range t.NumField() {
		tag, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if tag != "" && tag != "-" {
			out[tag] = true
		}
	}
	return out
}

// Backup copies a config aside before it is written in a newer shape, and
// returns where it went.
//
// Beside the original rather than in /tmp: this is the thing you want when an
// upgrade went wrong, and /tmp is cleared exactly when a machine is restarted
// to see whether the upgrade went wrong. Never overwrites an existing backup,
// so the oldest one — the one from before any of this started — is the one
// that survives.
func Backup(path string, version int) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	dest := fmt.Sprintf("%s.v%d.bak", path, version)
	if _, err := os.Stat(dest); err == nil {
		return dest, nil
	}
	if err := os.WriteFile(dest, b, 0o600); err != nil {
		return "", err
	}
	return dest, nil
}

// Save writes a node configuration, creating the directory if needed.
//
// Mode 0600 because this file holds all three private keys — the secrets whose
// disclosure lets someone else be this machine on the mesh.
func Save(path string, f *File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	b, err := f.encode()
	if err != nil {
		return err
	}

	// Write-then-rename: a node that loses its keys to a torn write has to be
	// re-admitted to the mesh by hand, and the daemon rewrites this file on
	// every netmap update.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".makima-node-*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}
