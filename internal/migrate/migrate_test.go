package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The shape `tailscale status --json` really has, trimmed to what is read.
const statusJSON = `{
  "Version": "1.102.3",
  "BackendState": "Running",
  "MagicDNSSuffix": "tailddc9d9.ts.net",
  "CurrentTailnet": {"Name": "you@example.com"},
  "Self": {"ID": "nSELF", "HostName": "Huiyun’s MacBook Air (2)", "DNSName": "huiyuns-macbook-air-2.tailddc9d9.ts.net.", "OS": "macOS", "TailscaleIPs": ["100.98.21.63", "fd7a:115c:a1e0::2833:1540"], "Online": false},
  "Peer": {
    "k1": {"ID": "nTENET", "HostName": "tenet", "DNSName": "tenet.tailddc9d9.ts.net.", "OS": "linux", "TailscaleIPs": ["100.102.72.87"], "Online": true, "sshHostKeys": ["ssh-ed25519 AAAAC3Nza"]},
    "k2": {"ID": "nOLD", "HostName": "justin06lee", "DNSName": "justin06lee.tailddc9d9.ts.net.", "OS": "linux", "TailscaleIPs": ["100.85.173.117"], "Online": false},
    "k3": {"ID": "nPHONE", "HostName": "iPhone", "DNSName": "iphone.tailddc9d9.ts.net.", "OS": "iOS", "TailscaleIPs": ["100.70.1.2"], "Online": true},
    "k4": {"ID": "nSHARED", "HostName": "friend", "DNSName": "friend.other.ts.net.", "OS": "linux", "TailscaleIPs": ["100.71.1.2"], "Online": true, "ShareeNode": true}
  }
}`

func TestParseStatus(t *testing.T) {
	tn, err := ParseStatus([]byte(statusJSON))
	if err != nil {
		t.Fatal(err)
	}
	if !tn.Running() || tn.Name != "you@example.com" {
		t.Fatalf("state %q name %q", tn.State, tn.Name)
	}
	if tn.Self.Name != "huiyuns-macbook-air-2" || !tn.Self.Local || !tn.Self.Online {
		t.Fatalf("self = %+v", tn.Self)
	}
	if len(tn.Peers) != 4 || !tn.Peers[0].Online {
		t.Fatalf("peers = %+v", tn.Peers)
	}
	var tenet Machine
	for _, p := range tn.Peers {
		if p.ID == "nTENET" {
			tenet = p
		}
	}
	if tenet.Name != "tenet" || tenet.IPv4() != "100.102.72.87" || len(tenet.HostKeys) != 1 {
		t.Fatalf("tenet = %+v", tenet)
	}
}

func TestNameFor(t *testing.T) {
	cases := map[[2]string]string{
		{"tenet.tail.ts.net.", ""}:                          "tenet",
		{"", "Huiyun’s MacBook Air (2)"}:                    "huiyun-s-macbook-air-2",
		{"", "!!!"}:                                         "device",
		{"UPPER_case.tail.ts.net", ""}:                      "upper-case",
		{"", strings.Repeat("a", 70)}:                       strings.Repeat("a", 63),
		{"-leading.tail.ts.net", ""}:                        "leading",
		{"x.tail.ts.net", "ignored because dns has a name"}: "x",
	}
	for in, want := range cases {
		if got := NameFor(in[0], in[1]); got != want {
			t.Errorf("NameFor(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
		if !ValidName(NameFor(in[0], in[1])) {
			t.Errorf("NameFor(%q, %q) is not a valid name", in[0], in[1])
		}
	}
	for _, bad := range []string{"", "a b", "a;rm", "UP", "-x"} {
		if ValidName(bad) {
			t.Errorf("ValidName(%q) = true", bad)
		}
	}
}

const linuxProbe = `Last login: yesterday
os=Linux
arch=x86_64
uid=0
user=root
hostname=tenet
sudo=root
tailscale=/usr/bin/tailscale
via=tailscale
init=systemd
addr=192.168.1.20
addr=100.102.72.87
addr=2600:1702::14
route=192.168.1.20
pkg=pacman
done=1
`

func TestParseFacts(t *testing.T) {
	f, err := ParseFacts(linuxProbe)
	if err != nil {
		t.Fatal(err)
	}
	if f.OS != "linux" || f.Arch != "amd64" || f.Sudo != "root" || f.Pkg != "pacman" || f.Via != "tailscale" || f.OpenSSH {
		t.Fatalf("facts = %+v", f)
	}
	if f.Public().IsValid() {
		t.Fatalf("a LAN and a Tailscale address are not public: %v", f.Public())
	}
	if f.Reach().String() != "192.168.1.20" {
		t.Fatalf("reach = %v", f.Reach())
	}
	if !f.Supported() {
		t.Fatal("linux/amd64 is supported")
	}

	vps, err := ParseFacts("os=Linux\narch=aarch64\nsudo=nopasswd\naddr=203.0.113.9\naddr=fe80::1%eth0\nroute=203.0.113.9\ndone=1\n")
	if err != nil {
		t.Fatal(err)
	}
	if vps.Public().String() != "203.0.113.9" || vps.Reach().String() != "203.0.113.9" || vps.Arch != "arm64" {
		t.Fatalf("vps = %+v", vps)
	}

	if _, err := ParseFacts("os=Linux\n"); err == nil {
		t.Fatal("a probe cut short must not parse")
	}
}

func TestProbeScriptIsPOSIX(t *testing.T) {
	// Run it here: it must finish, change nothing, and say everything.
	out, err := RunLocal(context.Background(), ProbeScript)
	if err != nil {
		t.Fatalf("probe failed here: %v\n%s", err, out)
	}
	f, err := ParseFacts(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.User == "" || f.Sudo == "" || f.OS == "" {
		t.Fatalf("facts = %+v", f)
	}
}

func scanWith(t *testing.T, sh *fakeShell) Plan {
	t.Helper()
	tn, err := ParseStatus([]byte(statusJSON))
	if err != nil {
		t.Fatal(err)
	}
	return Scan(context.Background(), tn, Scanner{
		SSH:     sh,
		Version: "v1.0.0",
		Local: func(context.Context, string) (string, error) {
			return "os=Darwin\narch=arm64\nuser=me\nsudo=password\naddr=192.168.1.199\nroute=192.168.1.199\ndone=1\n", nil
		},
	})
}

func TestScanJudgesAndRanks(t *testing.T) {
	sh := newFakeShell()
	p := scanWith(t, sh)

	byID := map[string]Candidate{}
	for _, c := range p.Machines {
		byID[c.ID] = c
	}
	if c := byID["nPHONE"]; c.Eligible || !strings.Contains(c.Why, "iPhone") {
		t.Errorf("phone: %+v", c)
	}
	if c := byID["nSHARED"]; c.Eligible || !strings.Contains(c.Why, "shared") {
		t.Errorf("shared: %+v", c)
	}
	if c := byID["nOLD"]; c.Eligible || !strings.Contains(c.Why, "offline") {
		t.Errorf("offline: %+v", c)
	}
	tenet := byID["nTENET"]
	if !tenet.Eligible || tenet.Reach != "192.168.1.20" || tenet.Access.User != "" {
		t.Errorf("tenet: %+v %+v", tenet, tenet.Access)
	}
	self := byID["nSELF"]
	if !self.Eligible || self.NeedsPassword {
		t.Errorf("self: the local sudo is the app's prompt, not a typed password: %+v", self)
	}
	// A Linux server beats a laptop.
	if p.Controller != "nTENET" {
		t.Errorf("controller = %s, want tenet", p.Controller)
	}
	if p.Advice == "" {
		t.Error("with no public address anywhere the plan should say what that means")
	}
	// Nothing but the probe was run anywhere.
	for _, c := range sh.calls {
		if c.script != ProbeScript {
			t.Errorf("scan ran %q on %s", c.script, c.target)
		}
	}
	if !sh.pinned["100.102.72.87"] {
		t.Error("tenet's published host key was not pinned")
	}
}

func TestScanTriesRootWhenRefused(t *testing.T) {
	sh := newFakeShell()
	sh.refuse[""] = true
	p := scanWith(t, sh)
	c, _ := p.Find("nTENET")
	if !c.Eligible || c.Access.User != "root" {
		t.Fatalf("tenet should be reached as root: %+v %+v", c, c.Access)
	}
}

func TestScanReportsTailscaleSSHCheck(t *testing.T) {
	sh := newFakeShell()
	sh.auth = "https://login.tailscale.com/a/abc"
	var mu sync.Mutex
	var urls []string
	tn, _ := ParseStatus([]byte(statusJSON))
	Scan(context.Background(), tn, Scanner{
		SSH: sh,
		Emit: func(e Event) {
			if e.Type == "auth" {
				mu.Lock()
				urls = append(urls, e.URL)
				mu.Unlock()
			}
		},
		Local: func(context.Context, string) (string, error) {
			return "os=Darwin\narch=arm64\nsudo=root\ndone=1\n", nil
		},
	})
	if len(urls) != 1 || urls[0] != sh.auth {
		t.Fatalf("auth events = %v", urls)
	}
}

func TestCheckAdvertise(t *testing.T) {
	for _, bad := range []string{"", "100.102.72.87", "http://100.64.0.1:8080", "tenet.tailddc9d9.ts.net", "https://tenet.tailddc9d9.ts.net", "[fd7a:115c:a1e0::1]:8080", "127.0.0.1", "0.0.0.0:8080"} {
		if err := CheckAdvertise(bad); err == nil {
			t.Errorf("CheckAdvertise(%q) accepted a Tailscale-only or unreachable address", bad)
		}
	}
	for _, good := range []string{"192.168.1.20", "203.0.113.9:8080", "https://makima.example.dev", "home.example.com"} {
		if err := CheckAdvertise(good); err != nil {
			t.Errorf("CheckAdvertise(%q) = %v", good, err)
		}
	}
}

func TestKitRoundTrip(t *testing.T) {
	files := map[string][]byte{}
	for _, b := range Binaries {
		files[b] = []byte("#!/bin/sh\necho " + b)
	}
	kit, err := Pack(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckKit(kit); err != nil {
		t.Fatal(err)
	}
	delete(files, "makimad")
	if _, err := Pack(files); err == nil {
		t.Fatal("a kit without makimad must not be made")
	}
	if CheckKit([]byte("not a tarball")) == nil {
		t.Fatal("garbage is not a kit")
	}
	if released("v0.2.0-15-gabc") || !released("v0.3.0") {
		t.Fatal("only release tags are downloadable")
	}
}

func TestActionArgs(t *testing.T) {
	// Pinned: privileged.rs spells these same command lines.
	cases := []struct {
		a    Action
		want string
	}{
		{Action{Kind: "migrate-host", Advertise: "192.168.1.20", Name: "tenet", Invites: 2}, "migrate host -json -advertise 192.168.1.20 -name tenet -invites 2"},
		{Action{Kind: "migrate-join", Name: "mac", Invite: "mk1_abc"}, "migrate join -name mac mk1_abc"},
		{Action{Kind: "migrate-cutover", Name: "mac", Controller: "tenet", Remove: true}, "migrate cutover -name mac -controller tenet -remove=true"},
		{Action{Kind: "migrate-cutover", Name: "mac", Controller: "mac", ServerSelf: true}, "migrate cutover -name mac -controller mac -server-self -remove=false"},
	}
	for _, c := range cases {
		if got := strings.Join(c.a.Args(), " "); got != c.want {
			t.Errorf("%s: %q, want %q", c.a.Kind, got, c.want)
		}
	}
}

func TestAsRootFeedsThePasswordFirst(t *testing.T) {
	j := &job{Candidate: &Candidate{Facts: &Facts{Sudo: "password"}}, password: "hunter2"}
	script, stdin := asRoot(j, "id -u", []byte("rest"))
	if !strings.HasPrefix(script, "sudo -k -S -p '' sh -c ") || string(stdin) != "hunter2\nrest" {
		t.Fatalf("%q %q", script, stdin)
	}
	j.Facts.Sudo = "root"
	if s, _ := asRoot(j, "id -u", nil); s != "id -u" {
		t.Fatalf("root needs no sudo: %q", s)
	}
	j.Facts.Sudo = "nopasswd"
	if s, _ := asRoot(j, "id -u", nil); !strings.HasPrefix(s, "sudo -n ") {
		t.Fatalf("%q", s)
	}
}

// --- the run, against machines that are not there ------------------------

type call struct {
	target Target
	script string
	stdin  string
}

type fakeShell struct {
	mu     sync.Mutex
	calls  []call
	pinned map[string]bool
	refuse map[string]bool // users whose login is refused
	auth   string

	probeFails map[string]bool   // tailscale IPs that cannot reach the server
	final      map[string]string // state each machine's switch ends in
	cutovers   []string          // machines a switch was started on, in order
}

func newFakeShell() *fakeShell {
	return &fakeShell{pinned: map[string]bool{}, refuse: map[string]bool{}, probeFails: map[string]bool{}, final: map[string]string{}}
}

func (f *fakeShell) Pin(addr string, keys []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(keys) > 0 {
		f.pinned[addr] = true
	}
	return nil
}

func (f *fakeShell) Run(ctx context.Context, t Target, script string, stdin []byte, onAuth func(string)) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, call{t, script, string(stdin)})
	refused := f.refuse[t.User]
	auth := f.auth
	f.mu.Unlock()

	if auth != "" && onAuth != nil {
		onAuth(auth)
	}
	if refused {
		return "", ErrDenied
	}
	// Seen through any number of layers of shell quoting.
	norm := strings.NewReplacer(`'\''`, "", "'", "").Replace(script)
	switch {
	case script == ProbeScript:
		return linuxProbe, nil
	case script == UploadScript:
		return "/tmp/makima-kit.abc123\n", nil
	case strings.Contains(script, "install -m 0755"):
		return "v1.0.0\n", nil
	case strings.Contains(norm, "migrate host"):
		n := 0
		fmt.Sscanf(norm[strings.Index(norm, "-invites ")+len("-invites "):], "%d", &n)
		inv := make([]string, n)
		for i := range inv {
			inv[i] = fmt.Sprintf("mk1_invite%d", i)
		}
		b, _ := json.Marshal(HostResult{Server: "http://192.168.1.20:8080", Invites: inv})
		return "starting...\n" + string(b) + "\n", nil
	case strings.Contains(norm, "migrate probe"):
		if f.probeFails[t.Addr] {
			return "", fmt.Errorf("no answer")
		}
		return "ok\n", nil
	case strings.Contains(norm, "migrate cutover"):
		f.mu.Lock()
		f.cutovers = append(f.cutovers, t.Addr)
		f.mu.Unlock()
		return "started\n", nil
	case strings.HasPrefix(script, "cat "):
		f.mu.Lock()
		s := f.final[t.Addr]
		f.mu.Unlock()
		if s == "" {
			s = StateDone
		}
		b, _ := json.Marshal(State{State: s, Detail: "reported by " + t.Addr, Path: "direct"})
		return string(b), nil
	}
	return "", fmt.Errorf("unexpected script %q", script)
}

// twoMachinePlan is this Mac and tenet, both movable.
func twoMachinePlan() Plan {
	return Plan{
		Tailnet: "t",
		Machines: []Candidate{
			{Machine: Machine{ID: "mac", Name: "mac", OS: "macOS", Local: true, Online: true, IPs: []string{"100.98.21.63"}},
				Facts: &Facts{OS: "darwin", Arch: "arm64", Sudo: "password", User: "me"}, Eligible: true, Reach: "192.168.1.199"},
			{Machine: Machine{ID: "tenet", Name: "tenet", OS: "linux", Online: true, IPs: []string{"100.102.72.87"}},
				Facts: &Facts{OS: "linux", Arch: "amd64", Sudo: "root", User: "root", Via: "tailscale"}, Access: &Access{},
				Eligible: true, Reach: "192.168.1.20"},
			{Machine: Machine{ID: "box", Name: "box", OS: "linux", Online: true, IPs: []string{"100.70.0.9"}},
				Facts: &Facts{OS: "linux", Arch: "arm64", Sudo: "password", User: "pi", OpenSSH: true}, Access: &Access{User: "pi"},
				Eligible: true, NeedsPassword: true, Reach: "192.168.1.30"},
		},
	}
}

type fakeLocal struct {
	mu      sync.Mutex
	actions []Action
	cutover string // state this machine's own switch ends in
}

func (l *fakeLocal) elevate(_ context.Context, a Action) (string, error) {
	l.mu.Lock()
	l.actions = append(l.actions, a)
	l.mu.Unlock()
	switch a.Kind {
	case "migrate-host":
		inv := make([]string, a.Invites)
		for i := range inv {
			inv[i] = fmt.Sprintf("mk1_local%d", i)
		}
		b, _ := json.Marshal(HostResult{Server: "http://192.168.1.199:8080", Invites: inv})
		return string(b), nil
	case "migrate-cutover":
		s := l.cutover
		if s == "" {
			s = StateDone
		}
		b, _ := json.Marshal(State{State: s, Removed: true})
		return "status...\n" + string(b), nil
	}
	return "", nil
}

func runner(sh *fakeShell, l *fakeLocal) *Runner {
	return &Runner{
		SSH:     sh,
		Version: "v1.0.0",
		Elevate: l.elevate,
		Probe:   func(context.Context, string) error { return nil },
		Peers:   func() map[string]MeshPeer { return nil },
		Pubkeys: func() string { return "ssh-ed25519 AAAAkey me@mac" },
		Kit: func(context.Context, string, string, string) ([]byte, string, error) {
			return []byte("kit"), "test", nil
		},
		Poll: time.Millisecond,
		Wait: time.Second,
	}
}

func outcomes(res Result) map[string]string {
	m := map[string]string{}
	for _, o := range res.Machines {
		m[o.ID] = o.Outcome
	}
	return m
}

func TestRunControllerRemote(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	ch := Choice{Plan: twoMachinePlan(), Controller: "tenet", Selected: []string{"mac", "tenet", "box"},
		Passwords: map[string]string{"box": "pw"}, Remove: true}
	res := runner(sh, l).Run(context.Background(), ch)

	if !res.OK || res.Server != "http://192.168.1.20:8080" {
		t.Fatalf("result = %+v", res)
	}
	if o := outcomes(res); o["mac"] != Moved || o["tenet"] != Moved || o["box"] != Moved {
		t.Fatalf("outcomes = %v", o)
	}
	// The controller switches before anybody else.
	if len(sh.cutovers) != 2 || sh.cutovers[0] != "100.102.72.87" {
		t.Fatalf("cutovers = %v", sh.cutovers)
	}
	// This machine joins, then switches last, pointed at the controller.
	if len(l.actions) != 2 || l.actions[0].Kind != "migrate-join" || l.actions[1].Kind != "migrate-cutover" ||
		l.actions[1].Controller != "tenet" || l.actions[1].ServerSelf || !l.actions[1].Remove {
		t.Fatalf("local actions = %+v", l.actions)
	}
	var sawBoxCutover, sawTenetCutover bool
	for _, c := range sh.calls {
		script := strings.NewReplacer(`'\''`, "", "'", "").Replace(c.script)
		if !strings.Contains(script, "migrate cutover") {
			continue
		}
		switch c.target.Addr {
		case "100.70.0.9":
			sawBoxCutover = true
			// Through sudo, password first, then the invite — never on
			// the command line.
			if !strings.HasPrefix(c.stdin, "pw\n{") || !strings.Contains(c.stdin, "mk1_invite") || strings.Contains(script, "mk1_") {
				t.Errorf("box cutover: script %q stdin %q", c.script, c.stdin)
			}
		case "100.102.72.87":
			sawTenetCutover = true
			if !strings.Contains(script, "-server-self") {
				t.Errorf("tenet holds the network: %q", c.script)
			}
			// Reached by Tailscale SSH with no sshd: it gets makima's.
			if !strings.Contains(script, "-ssh-user root") || !strings.Contains(c.stdin, "ssh-ed25519 AAAAkey") {
				t.Errorf("tenet should get makima's SSH server: %q %q", c.script, c.stdin)
			}
		}
	}
	if !sawBoxCutover || !sawTenetCutover {
		t.Fatal("a cutover was not started")
	}
}

func TestRunControllerLocal(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	ch := Choice{Plan: twoMachinePlan(), Controller: "mac", Selected: []string{"mac", "tenet"}, Remove: true}
	res := runner(sh, l).Run(context.Background(), ch)
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	if len(l.actions) != 2 || l.actions[0].Kind != "migrate-host" || l.actions[0].Invites != 1 ||
		l.actions[0].Advertise != "192.168.1.199" || l.actions[1].Kind != "migrate-cutover" || !l.actions[1].ServerSelf {
		t.Fatalf("local actions = %+v", l.actions)
	}
	if o := outcomes(res); o["box"] != Stayed {
		t.Fatalf("an unselected machine is left alone: %v", o)
	}
}

func TestRunLeavesUnreachableMachinesAlone(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	sh.probeFails["100.70.0.9"] = true
	ch := Choice{Plan: twoMachinePlan(), Controller: "tenet", Selected: []string{"mac", "tenet", "box"},
		Passwords: map[string]string{"box": "pw"}, Remove: true}
	res := runner(sh, l).Run(context.Background(), ch)
	if res.OK {
		t.Fatal("a machine stayed behind; the run is not wholly ok")
	}
	if o := outcomes(res); o["box"] != Stayed || o["tenet"] != Moved || o["mac"] != Moved {
		t.Fatalf("outcomes = %v", o)
	}
	for _, a := range sh.cutovers {
		if a == "100.70.0.9" {
			t.Fatal("a machine that cannot reach the server must never be switched")
		}
	}
}

func TestRunStopsWhenTheControllerRollsBack(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	sh.final["100.102.72.87"] = StateRolledBack
	ch := Choice{Plan: twoMachinePlan(), Controller: "tenet", Selected: []string{"mac", "tenet", "box"},
		Passwords: map[string]string{"box": "pw"}, Remove: true}
	res := runner(sh, l).Run(context.Background(), ch)
	if res.OK || res.Error == "" {
		t.Fatalf("result = %+v", res)
	}
	if len(sh.cutovers) != 1 {
		t.Fatalf("only the controller should have been tried: %v", sh.cutovers)
	}
	for _, a := range l.actions {
		if a.Kind == "migrate-cutover" {
			t.Fatal("this machine must not leave Tailscale when the controller could not")
		}
	}
	if o := outcomes(res); o["tenet"] != RolledBack || o["box"] != Stayed {
		t.Fatalf("outcomes = %v", o)
	}
}

func TestRunRefusesAMissingPassword(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	ch := Choice{Plan: twoMachinePlan(), Controller: "tenet", Selected: []string{"tenet", "box"}, Remove: true}
	res := runner(sh, l).Run(context.Background(), ch)
	if o := outcomes(res); o["box"] != Stayed {
		t.Fatalf("outcomes = %v", o)
	}
	for _, c := range sh.calls {
		if c.target.Addr == "100.70.0.9" {
			t.Fatalf("nothing should have been run on box: %q", c.script)
		}
	}
}

// --- Tailscale on the machine itself ----------------------------------------

type fakeHost struct {
	mu    sync.Mutex
	ran   []string
	files map[string]bool
	fail  map[string]bool
}

func (h *fakeHost) host(goos string) Host {
	return Host{
		GOOS: goos,
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			line := strings.Join(append([]string{name}, args...), " ")
			h.mu.Lock()
			h.ran = append(h.ran, line)
			h.mu.Unlock()
			for k := range h.fail {
				if strings.Contains(line, k) {
					return "", fmt.Errorf("%s failed", k)
				}
			}
			if strings.HasPrefix(line, "systemctl is-active") {
				return "active", nil
			}
			if strings.HasPrefix(line, "stat -f %Su /dev/console") {
				return "me", nil
			}
			return "", nil
		},
		Exists: func(p string) bool { return h.files[p] },
	}
}

func (h *fakeHost) did(sub string) bool {
	for _, l := range h.ran {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func TestTailscaleOnArchLinux(t *testing.T) {
	h := &fakeHost{files: map[string]bool{"/run/systemd/system": true, "/usr/bin/tailscale": true, "/usr/bin/tailscaled": true},
		fail: map[string]bool{"dpkg-query": true, "rpm -q": true}}
	ts, ok := FindTailscale(context.Background(), h.host("linux"))
	if !ok || ts.Kind != "systemd" || ts.Pkg != "pacman" {
		t.Fatalf("found %+v", ts)
	}
	if err := ts.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.did("systemctl stop tailscaled") || !h.did("/usr/bin/tailscaled --cleanup") {
		t.Fatalf("stop ran %v", h.ran)
	}
	if err := ts.Start(context.Background()); err != nil || !h.did("systemctl start tailscaled") {
		t.Fatalf("start ran %v", h.ran)
	}
	if _, err := ts.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tailscale logout", "systemctl disable --now tailscaled", "pacman -Rns --noconfirm tailscale", "rm -rf /var/lib/tailscale"} {
		if !h.did(want) {
			t.Errorf("remove did not run %q: %v", want, h.ran)
		}
	}
}

func TestTailscaleMacApp(t *testing.T) {
	h := &fakeHost{files: map[string]bool{"/Applications/Tailscale.app": true, "/Applications/Tailscale.app/Contents/MacOS/Tailscale": true}}
	ts, ok := FindTailscale(context.Background(), h.host("darwin"))
	if !ok || ts.Kind != "app" {
		t.Fatalf("found %+v", ts)
	}
	_ = ts.Stop(context.Background())
	if !h.did("sudo -u me /Applications/Tailscale.app/Contents/MacOS/Tailscale down") {
		t.Fatalf("the app's CLI should run as the person at the console: %v", h.ran)
	}
	notes, _ := ts.Remove(context.Background())
	for _, want := range []string{"Tailscale logout", "configure mac-vpn uninstall", "configure sysext deactivate", "rm -rf /Applications/Tailscale.app"} {
		if !h.did(want) {
			t.Errorf("remove did not run %q: %v", want, h.ran)
		}
	}
	_ = notes
}

func TestTailscaleRemoveKeepsGoingAndSaysWhat(t *testing.T) {
	h := &fakeHost{files: map[string]bool{"/run/systemd/system": true, "/usr/bin/tailscale": true},
		fail: map[string]bool{"logout": true, "dpkg-query": true, "rpm -q": true, "pacman -Rns": true}}
	ts, _ := FindTailscale(context.Background(), h.host("linux"))
	notes, err := ts.Remove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 2 || !strings.Contains(notes[0], "admin console") || !strings.Contains(notes[1], "by hand") {
		t.Fatalf("notes = %q", notes)
	}
	if h.did("rm -rf /var/lib/tailscale") {
		t.Fatal("state must stay while the package is still installed")
	}
}

func TestRankPrefersAPublicAddress(t *testing.T) {
	p := Plan{Machines: []Candidate{
		{Machine: Machine{ID: "laptop", Name: "macbook-air", Local: true}, Eligible: true, Reach: "192.168.1.2", Facts: &Facts{OS: "darwin", Holds: true}},
		{Machine: Machine{ID: "vps", Name: "vps"}, Eligible: true, Public: "203.0.113.9", Reach: "203.0.113.9", Facts: &Facts{OS: "linux"}},
		{Machine: Machine{ID: "server", Name: "tenet"}, Eligible: true, Reach: "192.168.1.20", Facts: &Facts{OS: "linux"}},
	}}
	rank(&p)
	if p.Controller != "vps" || p.Advice != "" {
		t.Fatalf("controller %s advice %q", p.Controller, p.Advice)
	}
	p.Machines = p.Machines[:1:1]
	p.Machines = append(p.Machines, Candidate{Machine: Machine{ID: "server", Name: "tenet"}, Eligible: true, Reach: "192.168.1.20", Facts: &Facts{OS: "linux"}})
	for i := range p.Machines {
		p.Machines[i].Score = 0
	}
	rank(&p)
	if p.Controller != "server" {
		t.Fatalf("a server that stays on beats a laptop holding a first-try network: %s", p.Controller)
	}
}

func TestRunTellsOthersWhenTheControllerSwitchesLast(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	plan := twoMachinePlan()
	plan.Machines[0].Facts.OS = "linux"
	plan.Machines[0].Facts.Tailscale = "/usr/bin/tailscale"
	res := runner(sh, l).Run(context.Background(), Choice{Plan: plan, Controller: "mac", Selected: []string{"mac", "tenet"}, Remove: true})
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	for _, c := range sh.calls {
		if strings.Contains(c.script, "cutover") && !strings.Contains(c.script, "controller-on-tailscale") {
			t.Fatalf("tenet cannot test the tunnel to a controller still behind Tailscale's firewall: %q", c.script)
		}
	}
}

// With MAKIMA_KITS pointing at `make kits` output, the kits are what the
// installer expects. Skipped otherwise.
func TestBuiltKits(t *testing.T) {
	if os.Getenv("MAKIMA_KITS") == "" {
		t.Skip("MAKIMA_KITS is not set")
	}
	for _, p := range []string{"linux/amd64", "linux/arm64", "linux/arm"} {
		goos, goarch, _ := strings.Cut(p, "/")
		kit, from, err := KitFor(context.Background(), goos, goarch, "dev")
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		t.Logf("%s: %d bytes from %s", p, len(kit), from)
	}
}
