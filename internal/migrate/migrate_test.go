package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// Run for real, in a home of its own: a file with no newline at the end, a
// key already there and one that is not.
func TestAuthorizeScript(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	file := filepath.Join(home, ".ssh", "authorized_keys")
	os.WriteFile(file, []byte("ssh-ed25519 AAAAold laptop"), 0o600)

	run := func(keys string) string {
		cmd := exec.Command("sh", "-c", AuthorizeScript)
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
		cmd.Stdin = strings.NewReader(keys)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if out := run("ssh-ed25519 AAAAold laptop\nssh-ed25519 AAAAnew me@mac\n\n"); out != "added=1" {
		t.Fatalf("first run said %q", out)
	}
	if out := run("ssh-ed25519 AAAAnew me@mac\n"); out != "added=0" {
		t.Fatalf("a key already there was added again: %q", out)
	}
	b, _ := os.ReadFile(file)
	if string(b) != "ssh-ed25519 AAAAold laptop\nssh-ed25519 AAAAnew me@mac\n" {
		t.Fatalf("authorized_keys = %q", b)
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
		{Action{Kind: "migrate-retire"}, "migrate retire"},
	}
	for _, c := range cases {
		if got := strings.Join(c.a.Args(), " "); got != c.want {
			t.Errorf("%s: %q, want %q", c.a.Kind, got, c.want)
		}
	}
	if b, _ := json.Marshal(Action{Kind: "migrate-retire"}); string(b) != `{"kind":"migrate-retire"}` {
		t.Errorf("the app is sent %s", b)
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

// norm is a script with its layers of shell quoting taken off.
func (c call) norm() string { return strings.NewReplacer(`'\''`, "", "'", "").Replace(c.script) }

type fakeShell struct {
	mu     sync.Mutex
	calls  []call
	pinned map[string]bool
	refuse map[string]bool // users whose login is refused
	auth   string

	probeFails  map[string]bool // Tailscale addresses that cannot reach the server
	meshDown    map[string]bool // makima addresses ssh over makima cannot get into
	retireFails map[string]bool // makima addresses where removing Tailscale fails
}

func newFakeShell() *fakeShell {
	return &fakeShell{pinned: map[string]bool{}, refuse: map[string]bool{}, probeFails: map[string]bool{}, meshDown: map[string]bool{}, retireFails: map[string]bool{}}
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
	c := call{t, script, string(stdin)}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	refused := f.refuse[t.User]
	auth := f.auth
	f.mu.Unlock()

	if auth != "" && onAuth != nil {
		onAuth(auth)
	}
	if refused {
		return "", ErrDenied
	}
	norm := c.norm()
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case script == ProbeScript:
		return linuxProbe, nil
	case script == UploadScript:
		return "/tmp/makima-kit.abc123\n", nil
	case strings.Contains(script, "install -m 0755"):
		return "v1.0.0\n", nil
	case script == AuthorizeScript:
		return "added=1\n", nil
	case script == CheckScript:
		if f.meshDown[t.Addr] {
			return "", ErrDenied
		}
		return "makima-ok\n", nil
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
	case strings.Contains(norm, "migrate join"):
		return "joined\n", nil
	case strings.Contains(norm, "migrate retire"):
		if f.retireFails[t.Addr] {
			return "", fmt.Errorf("pacman is locked")
		}
		return `{"removed":true}` + "\n", nil
	}
	return "", fmt.Errorf("unexpected script %q", script)
}

// ran is every call whose script does sub, in order, with where it came in
// the whole run.
func (f *fakeShell) ran(sub string) (calls []call, at []int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, c := range f.calls {
		if c.script == sub || strings.Contains(c.norm(), sub) {
			calls = append(calls, c)
			at = append(at, i)
		}
	}
	return calls, at
}

// twoMachinePlan is this Mac, tenet — reached through Tailscale SSH with no
// sshd — and box, which has an sshd and a sudo that wants a password.
func twoMachinePlan() Plan {
	return Plan{
		Tailnet: "t",
		Machines: []Candidate{
			{Machine: Machine{ID: "mac", Name: "mac", OS: "macOS", Local: true, Online: true, IPs: []string{"100.98.21.63"}},
				Facts: &Facts{OS: "darwin", Arch: "arm64", Sudo: "password", User: "me"}, Eligible: true, Reach: "192.168.1.199"},
			{Machine: Machine{ID: "tenet", Name: "tenet", OS: "linux", Online: true, IPs: []string{"100.102.72.87"}, HostKeys: []string{"ssh-ed25519 AAAAtenet"}},
				Facts: &Facts{OS: "linux", Arch: "amd64", Sudo: "root", User: "root", Via: "tailscale"}, Access: &Access{},
				Eligible: true, Reach: "192.168.1.20"},
			{Machine: Machine{ID: "box", Name: "box", OS: "linux", Online: true, IPs: []string{"100.70.0.9"}, HostKeys: []string{"ssh-ed25519 AAAAbox"}},
				Facts: &Facts{OS: "linux", Arch: "arm64", Sudo: "password", User: "pi", OpenSSH: true}, Access: &Access{User: "pi"},
				Eligible: true, NeedsPassword: true, Reach: "192.168.1.30"},
		},
	}
}

func everyone() Choice {
	return Choice{Plan: twoMachinePlan(), Controller: "tenet", Selected: []string{"mac", "tenet", "box"},
		Passwords: map[string]string{"box": "pw"}, Remove: true}
}

type fakeLocal struct {
	mu       sync.Mutex
	actions  []Action
	joinFail bool
}

func (l *fakeLocal) elevate(_ context.Context, a Action) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.actions = append(l.actions, a)
	switch a.Kind {
	case "migrate-host":
		inv := make([]string, a.Invites)
		for i := range inv {
			inv[i] = fmt.Sprintf("mk1_local%d", i)
		}
		b, _ := json.Marshal(HostResult{Server: "http://192.168.1.199:8080", Invites: inv})
		return string(b), nil
	case "migrate-join":
		if l.joinFail {
			return "", fmt.Errorf("it would not start")
		}
		return "joined", nil
	case "migrate-retire":
		return "status...\n" + `{"removed":true}`, nil
	}
	return "", nil
}

func (l *fakeLocal) kinds() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var k []string
	for _, a := range l.actions {
		k = append(k, a.Kind)
	}
	return strings.Join(k, ",")
}

func runner(sh *fakeShell, l *fakeLocal, peers map[string]MeshPeer) *Runner {
	if peers == nil {
		peers = map[string]MeshPeer{
			"mac":   {Address: "10.77.0.9", Online: true, Direct: true},
			"tenet": {Address: "10.77.0.1", Online: true, Direct: true},
			"box":   {Address: "10.77.0.2", Online: true},
		}
	}
	return &Runner{
		SSH:     sh,
		Version: "v1.0.0",
		Elevate: l.elevate,
		Probe:   func(context.Context, string) error { return nil },
		Peers:   func() map[string]MeshPeer { return peers },
		Keys:    func() Keys { return Keys{Public: "ssh-ed25519 AAAAkey me@mac"} },
		Kit: func(context.Context, string, string, string) ([]byte, string, error) {
			return []byte("kit"), "test", nil
		},
		Wait: 50 * time.Millisecond,
		Poll: time.Millisecond,
	}
}

func outcomes(res Result) map[string]Outcome {
	m := map[string]Outcome{}
	for _, o := range res.Machines {
		m[o.ID] = o
	}
	return m
}

func TestRunAddsEverythingBeforeRemovingAnything(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	res := runner(sh, l, nil).Run(context.Background(), everyone())

	if !res.OK || res.Server != "http://192.168.1.20:8080" {
		t.Fatalf("result = %+v", res)
	}
	for id, o := range outcomes(res) {
		if o.Outcome != Moved {
			t.Errorf("%s: %+v", id, o)
		}
	}

	// Removal happens over makima and nothing else — and only after every
	// device has joined.
	retires, retireAt := sh.ran("migrate retire")
	if len(retires) != 2 {
		t.Fatalf("retired over ssh: %+v", retires)
	}
	joins, joinAt := sh.ran("migrate join")
	for _, i := range joinAt {
		if i > retireAt[0] {
			t.Fatal("Tailscale came off a device before every device had joined")
		}
	}
	for _, c := range retires {
		switch c.target.Addr {
		case "10.77.0.1":
			if c.target.Port != 2222 {
				t.Errorf("tenet has no sshd; it is reached through makima's own: %+v", c.target)
			}
		case "10.77.0.2":
			if c.target.Port != 0 || c.target.User != "pi" || !strings.HasPrefix(c.stdin, "pw\n") {
				t.Errorf("box: %+v %q", c.target, c.stdin)
			}
		default:
			t.Errorf("Tailscale was removed over %s, which is not makima", c.target.Addr)
		}
	}
	// And each device was logged in to over makima before it lost Tailscale.
	checks, checkAt := sh.ran(CheckScript)
	for i, r := range retires {
		reached := false
		for k, c := range checks {
			if c.target.Addr == r.target.Addr && checkAt[k] < retireAt[i] {
				reached = true
			}
		}
		if !reached {
			t.Errorf("%s lost Tailscale without being reached over makima first", r.target.Addr)
		}
	}

	// Joining is over Tailscale, with the invite on stdin, never on a
	// command line.
	for _, c := range joins {
		if strings.HasPrefix(c.target.Addr, "10.77.") {
			t.Errorf("joined over makima: %s", c.target.Addr)
		}
		if strings.Contains(c.script, "mk1_") || !strings.Contains(c.stdin, "mk1_invite") {
			t.Errorf("join: script %q stdin %q", c.script, c.stdin)
		}
		if c.target.Addr == "100.70.0.9" && !strings.HasPrefix(c.stdin, "pw\n{") {
			t.Errorf("box's sudo password goes first: %q", c.stdin)
		}
	}

	// box has an sshd: your keys go in its authorized_keys, as pi, not root.
	// tenet has none: makima's own SSH server takes them, when it hosts.
	auth, _ := sh.ran(AuthorizeScript)
	if len(auth) != 1 || auth[0].target.Addr != "100.70.0.9" || !strings.Contains(auth[0].stdin, "AAAAkey") {
		t.Fatalf("authorized: %+v", auth)
	}
	hosts, _ := sh.ran("migrate host")
	if len(hosts) != 1 || !strings.Contains(hosts[0].norm(), "-ssh-user root") || !strings.Contains(hosts[0].stdin, "AAAAkey") {
		t.Fatalf("host: %+v", hosts)
	}

	// This device joined, and lost Tailscale last.
	if k := l.kinds(); k != "migrate-join,migrate-retire" {
		t.Fatalf("local actions = %s", k)
	}
}

func TestRunNeedsAnSSHKey(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	r := runner(sh, l, nil)
	r.Keys = func() Keys { return Keys{} }
	res := r.Run(context.Background(), everyone())
	if res.OK || !strings.Contains(res.Error, "ssh-keygen") {
		t.Fatalf("result = %+v", res)
	}
	if len(sh.calls) != 0 || len(l.actions) != 0 {
		t.Fatalf("something was done: %v %v", sh.calls, l.actions)
	}
}

// A key with a passphrase and no agent holding it would be put on every
// machine and then refused at every login: the run stops first, and says how
// to unlock it.
func TestRunNeedsAKeyItCanUseUnattended(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	r := runner(sh, l, nil)
	r.Keys = func() Keys { return Keys{Locked: []string{"/keys/id_ed25519_me"}} }
	res := r.Run(context.Background(), everyone())
	if res.OK || !strings.Contains(res.Error, "passphrase") || !strings.Contains(res.Error, "ssh-add") || !strings.Contains(res.Error, "/keys/id_ed25519_me") {
		t.Fatalf("result = %+v", res)
	}
	if len(sh.calls) != 0 || len(l.actions) != 0 {
		t.Fatalf("something was done: %v %v", sh.calls, l.actions)
	}
}

func TestFindKeys(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	dir := t.TempDir()
	gen := func(name, pass string) string {
		p := filepath.Join(dir, name)
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", pass, "-C", name, "-f", p).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v %s", err, out)
		}
		b, _ := os.ReadFile(p + ".pub")
		return strings.TrimSpace(string(b))
	}
	open := gen("id_open", "")
	locked := gen("id_locked", "secret")
	held := gen("id_held", "secret")
	os.WriteFile(filepath.Join(dir, "orphan.pub"), []byte("ssh-ed25519 AAAAorphan nobody\n"), 0o644)

	k := findKeys(held+"\n", dir)
	if !strings.Contains(k.Public, open) || !strings.Contains(k.Public, held) || strings.Contains(k.Public, locked) || strings.Contains(k.Public, "orphan") {
		t.Errorf("public = %q", k.Public)
	}
	if len(k.Files) != 1 || k.Files[0] != filepath.Join(dir, "id_open") {
		t.Errorf("files = %v", k.Files)
	}
	if len(k.Locked) != 1 || k.Locked[0] != filepath.Join(dir, "id_locked") {
		t.Errorf("locked = %v", k.Locked)
	}
}

// A device that cannot reach the server without Tailscale never joins, and
// this device keeps Tailscale for it.
func TestRunLeavesAMachineThatCannotReachTheServerOnTailscale(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	sh.probeFails["100.70.0.9"] = true
	res := runner(sh, l, nil).Run(context.Background(), everyone())
	o := outcomes(res)
	if res.OK || o["box"].Outcome != Stayed || o["tenet"].Outcome != Moved || o["mac"].Outcome != Both {
		t.Fatalf("outcomes = %+v", o)
	}
	if !strings.Contains(o["mac"].Detail, "box") {
		t.Errorf("this device should say why it kept Tailscale: %q", o["mac"].Detail)
	}
	joins, _ := sh.ran("migrate join")
	for _, c := range joins {
		if c.target.Addr == "100.70.0.9" {
			t.Fatal("box joined")
		}
	}
	if strings.Contains(l.kinds(), "retire") {
		t.Fatal("this device lost Tailscale while box still needs it")
	}
}

// Joined, but ssh over makima does not get in: Tailscale stays.
func TestRunKeepsTailscaleWhereMakimaCannotBeReached(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	sh.meshDown["10.77.0.2"] = true
	res := runner(sh, l, nil).Run(context.Background(), everyone())
	o := outcomes(res)
	if o["box"].Outcome != Stayed || !strings.Contains(o["box"].Detail, "ssh over makima") || o["tenet"].Outcome != Moved || o["mac"].Outcome != Both {
		t.Fatalf("outcomes = %+v", o)
	}
	retires, _ := sh.ran("migrate retire")
	for _, c := range retires {
		if c.target.Addr == "10.77.0.2" {
			t.Fatal("box lost Tailscale without being reached over makima")
		}
	}
}

// A device on the network that no connection ever came up to is most likely
// behind a firewall, and the run says so.
func TestRunNamesAFirewallWhenNoConnectionComesUp(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	res := runner(sh, l, map[string]MeshPeer{
		"mac":   {Address: "10.77.0.9", Online: true},
		"tenet": {Address: "10.77.0.1", Online: true},
		"box":   {Address: "10.77.0.2", Online: false},
	}).Run(context.Background(), everyone())
	if o := outcomes(res)["box"]; o.Outcome != Stayed || !strings.Contains(o.Detail, "UDP 51820") {
		t.Fatalf("box = %+v", o)
	}
}

func TestRunWithoutRemovalLeavesTailscaleRunning(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	ch := everyone()
	ch.Remove = false
	res := runner(sh, l, nil).Run(context.Background(), ch)
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	for id, o := range outcomes(res) {
		if o.Outcome != Both {
			t.Errorf("%s: %+v", id, o)
		}
	}
	if retires, _ := sh.ran("migrate retire"); len(retires) != 0 || strings.Contains(l.kinds(), "retire") {
		t.Fatal("Tailscale was removed")
	}
}

// Tailscale that will not come off leaves the device on both, and says so.
func TestRunReportsATailscaleThatWouldNotGo(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	sh.retireFails["10.77.0.1"] = true
	res := runner(sh, l, nil).Run(context.Background(), everyone())
	o := outcomes(res)
	if o["tenet"].Outcome != Both || !strings.Contains(o["tenet"].Detail, "pacman is locked") || o["mac"].Outcome != Both {
		t.Fatalf("outcomes = %+v", o)
	}
}

func TestRunControllerLocal(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	ch := Choice{Plan: twoMachinePlan(), Controller: "mac", Selected: []string{"mac", "tenet"}, Remove: true}
	res := runner(sh, l, nil).Run(context.Background(), ch)
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	if l.kinds() != "migrate-host,migrate-retire" || l.actions[0].Invites != 1 || l.actions[0].Advertise != "192.168.1.199" {
		t.Fatalf("local actions = %+v", l.actions)
	}
	if o := outcomes(res); o["box"].Outcome != Stayed || o["tenet"].Outcome != Moved {
		t.Fatalf("outcomes = %+v", o)
	}
}

// This device is what reaches the others over makima. If it cannot join,
// nothing can be reached, and Tailscale comes off nothing.
func TestRunRemovesNothingWhenThisDeviceCannotJoin(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{joinFail: true}
	res := runner(sh, l, nil).Run(context.Background(), everyone())
	if res.OK || !strings.Contains(res.Error, "removed from none") {
		t.Fatalf("result = %+v", res)
	}
	if retires, _ := sh.ran("migrate retire"); len(retires) != 0 || strings.Contains(l.kinds(), "retire") {
		t.Fatal("Tailscale was removed")
	}
	for id, o := range outcomes(res) {
		if o.Outcome != Stayed {
			t.Errorf("%s: %+v", id, o)
		}
	}
}

func TestRunRefusesAMissingPassword(t *testing.T) {
	sh, l := newFakeShell(), &fakeLocal{}
	ch := everyone()
	ch.Passwords = nil
	res := runner(sh, l, nil).Run(context.Background(), ch)
	if o := outcomes(res); o["box"].Outcome != Stayed {
		t.Fatalf("outcomes = %+v", o)
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
	if _, err := ts.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tailscale logout", "systemctl disable --now tailscaled", "/usr/bin/tailscaled --cleanup", "pacman -Rns --noconfirm tailscale", "rm -rf /var/lib/tailscale"} {
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
	if _, err := ts.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The app's CLI talks to the app in the console user's session, so it
	// runs as them.
	for _, want := range []string{"sudo -u me /Applications/Tailscale.app/Contents/MacOS/Tailscale logout", "configure mac-vpn uninstall", "configure sysext deactivate", "rm -rf /Applications/Tailscale.app"} {
		if !h.did(want) {
			t.Errorf("remove did not run %q: %v", want, h.ran)
		}
	}
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
