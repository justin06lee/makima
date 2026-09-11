// Package migrate moves a whole tailnet onto makima.
//
// The trick it relies on is that Tailscale is already the thing that can reach
// every machine. So the move is made through it: SSH over the tailnet to each
// machine, put makima there, start a network on whichever machine the person
// picks to hold it, and switch each machine over — and only once a machine is
// provably on makima does Tailscale come off it. A machine that does not come
// up on makima puts Tailscale back by itself, so the worst a failed switch can
// do is leave a machine exactly where it started.
//
// The package is split by where code runs. tailscale.go, facts.go, ssh.go,
// kit.go, plan.go and run.go run on the machine the person is sitting at, as
// that person. state.go and tsctl.go run on the machine being switched, as
// root — see cmd/makima/migrate.go for the commands that wrap them.
package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// ErrNoTailscale says there is no Tailscale here to move away from.
var ErrNoTailscale = errors.New("tailscale is not installed here")

// Tailscale's own address space. Anything in these is only reachable while
// Tailscale runs, which is exactly what a migration is about to stop — so no
// address in them may ever be what a machine uses to find makima.
var (
	tsRange4 = netip.MustParsePrefix("100.64.0.0/10")
	tsRange6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// IsTailscaleAddr reports whether an address only exists inside a tailnet.
func IsTailscaleAddr(a netip.Addr) bool {
	a = a.Unmap()
	return tsRange4.Contains(a) || tsRange6.Contains(a)
}

// IsTailscaleHost reports whether a host — an address or a name — only
// resolves or routes while Tailscale is up.
func IsTailscaleHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		return IsTailscaleAddr(a)
	}
	return strings.HasSuffix(strings.TrimSuffix(host, "."), ".ts.net")
}

// Machine is one device on the tailnet, as Tailscale describes it.
type Machine struct {
	// ID is Tailscale's stable node ID. It is what the app and the run refer
	// to a machine by, because names can collide and change.
	ID string `json:"id"`

	// Name is what the machine will be called on makima: the first label of
	// its MagicDNS name, so `tenet.tailxxxx.ts.net` becomes `tenet.makima`
	// and nobody has to learn a second set of names.
	Name string `json:"name"`

	Host   string   `json:"host"`
	DNS    string   `json:"dns,omitempty"`
	OS     string   `json:"os"`
	IPs    []string `json:"ips"`
	Online bool     `json:"online"`
	Local  bool     `json:"local,omitempty"`

	// Shared is a machine somebody else shared into this tailnet. It is
	// theirs, and it is not ours to reinstall.
	Shared bool `json:"shared,omitempty"`

	// HostKeys are the SSH host keys Tailscale publishes for the machine.
	// They are pinned for every connection the migration makes, so nothing
	// is trusted on first use and the person's known_hosts is never touched.
	HostKeys []string `json:"host_keys,omitempty"`
}

// IPv4 is the machine's Tailscale IPv4 address, the one SSH is pointed at.
func (m Machine) IPv4() string {
	for _, s := range m.IPs {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return s
		}
	}
	if len(m.IPs) > 0 {
		return m.IPs[0]
	}
	return ""
}

// Tailnet is everything Tailscale says about the network this machine is on.
type Tailnet struct {
	Name    string    `json:"name"`
	State   string    `json:"state"`
	Self    Machine   `json:"self"`
	Peers   []Machine `json:"peers"`
	Version string    `json:"version,omitempty"`
}

// Running says Tailscale is connected, not merely installed.
func (t *Tailnet) Running() bool { return t != nil && t.State == "Running" }

// All is Self followed by the peers.
func (t *Tailnet) All() []Machine {
	return append([]Machine{t.Self}, t.Peers...)
}

// The parts of `tailscale status --json` the migration reads.
type tsPeer struct {
	ID           string   `json:"ID"`
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	OS           string   `json:"OS"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
	ShareeNode   bool     `json:"ShareeNode"`
	SSHHostKeys  []string `json:"sshHostKeys"`
}

type tsStatus struct {
	Version        string             `json:"Version"`
	BackendState   string             `json:"BackendState"`
	MagicDNSSuffix string             `json:"MagicDNSSuffix"`
	Self           *tsPeer            `json:"Self"`
	Peer           map[string]*tsPeer `json:"Peer"`
	CurrentTailnet *struct {
		Name string `json:"Name"`
	} `json:"CurrentTailnet"`
}

// CLI finds the tailscale command.
//
// PATH first, then where each way of installing it puts the binary. The app is
// started by launchd with a PATH of /usr/bin:/bin:/usr/sbin:/sbin, so the
// absolute paths are what actually find it from a window.
func CLI() (string, error) {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p, nil
	}
	for _, p := range []string{
		"/Applications/Tailscale.app/Contents/MacOS/Tailscale",
		"/usr/local/bin/tailscale",
		"/opt/homebrew/bin/tailscale",
		"/usr/bin/tailscale",
		"/usr/sbin/tailscale",
		"/run/current-system/sw/bin/tailscale",
	} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", ErrNoTailscale
}

// Status asks the local Tailscale what the tailnet looks like.
func Status(ctx context.Context) (*Tailnet, error) {
	cli, err := CLI()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, cli, "status", "--json").Output()
	if err != nil && len(out) == 0 {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("tailscale status: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("tailscale status: %w", err)
	}
	return ParseStatus(out)
}

// ParseStatus reads `tailscale status --json`.
func ParseStatus(raw []byte) (*Tailnet, error) {
	var st tsStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("read tailscale status: %w", err)
	}
	t := &Tailnet{State: st.BackendState, Version: st.Version}
	if st.CurrentTailnet != nil {
		t.Name = st.CurrentTailnet.Name
	}
	if t.Name == "" {
		t.Name = strings.TrimSuffix(st.MagicDNSSuffix, ".")
	}
	if st.Self != nil {
		t.Self = machineFrom(st.Self)
		t.Self.Local = true
		t.Self.Online = true
	}
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		t.Peers = append(t.Peers, machineFrom(p))
	}
	// Online first, then by name, so the list reads the same way twice.
	sort.Slice(t.Peers, func(i, j int) bool {
		if t.Peers[i].Online != t.Peers[j].Online {
			return t.Peers[i].Online
		}
		return t.Peers[i].Name < t.Peers[j].Name
	})
	return t, nil
}

func machineFrom(p *tsPeer) Machine {
	return Machine{
		ID:       p.ID,
		Name:     NameFor(p.DNSName, p.HostName),
		Host:     p.HostName,
		DNS:      strings.TrimSuffix(p.DNSName, "."),
		OS:       p.OS,
		IPs:      p.TailscaleIPs,
		Online:   p.Online,
		Shared:   p.ShareeNode,
		HostKeys: p.SSHHostKeys,
	}
}

// NameFor turns a machine's MagicDNS name, or failing that its host name, into
// a name makima will accept: lowercase letters, digits and hyphens.
func NameFor(dnsName, hostName string) string {
	if label, _, _ := strings.Cut(strings.TrimSuffix(dnsName, "."), "."); label != "" {
		if n := sanitize(label); n != "" {
			return n
		}
	}
	if n := sanitize(hostName); n != "" {
		return n
	}
	return "device"
}

func sanitize(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	n := strings.TrimRight(b.String(), "-")
	if len(n) > 63 {
		n = strings.TrimRight(n[:63], "-")
	}
	return n
}

// ValidName says whether a name is one this package would have produced.
// Names reach root on other machines as arguments, so they are checked again
// wherever they arrive.
func ValidName(n string) bool {
	return n != "" && len(n) <= 63 && sanitize(n) == n
}
