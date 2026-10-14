package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/sshd"
)

// fakeFarEnd answers a prober's questions from a table instead of a network.
type fakeFarEnd struct {
	ports    map[int]reach
	listed   []sshd.Account
	open     map[string]bool // "port/account" a key-only login works for
	sshUser  string
	thisUser string
}

func (f fakeFarEnd) dial(port int) reach                 { return f.ports[port] }
func (f fakeFarEnd) listAccounts(int) []sshd.Account     { return f.listed }
func (f fakeFarEnd) defaultUser() string                 { return f.sshUser }
func (f fakeFarEnd) me() string                          { return f.thisUser }
func (f fakeFarEnd) opens(port int, account string) bool { return f.open[portAccount(port, account)] }

// portAccount is how fakeFarEnd.open is keyed: port 0 is the system's sshd.
func portAccount(port int, account string) string {
	if port == 0 {
		port = 22
	}
	return fmt.Sprintf("%d/%s", port, account)
}

func names(as []sshd.Account) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.Name)
	}
	return out
}

// The Jetson asking for a shell on the Mac with no key there: the password
// asked for is the Mac's owner's, and the prompt — "huiyunlee's password:" —
// is all that is said. It used to be the Jetson's own account name, which
// does not exist on the Mac, so every password was wrong.
func TestNoKeyAsksForTheFarEndOwnersPassword(t *testing.T) {
	f := fakeFarEnd{
		ports:    map[int]reach{sshd.DefaultPort: reachRefused, 22: reachOpen},
		sshUser:  "midna",
		thisUser: "midna",
	}
	r, err := planRoute("mac", farEnd{addr: "10.77.0.2", owner: "huiyunlee"}, f)
	if err != nil {
		t.Fatal(err)
	}
	if r.password != "huiyunlee" {
		t.Errorf("asks for %q's password, want the owner's", r.password)
	}
	if r.note != "" {
		t.Errorf("said more than the prompt does: %q", r.note)
	}
	if got, _ := pickAccount("mac", r, f.sshUser); got != "huiyunlee" {
		t.Errorf("logs in as %q", got)
	}
}

// With no owner to go on, ssh's own choice stands — and is named, so a
// password that keeps failing has an explanation on the screen.
func TestNoKeyAndNoOwnerNamesTheAccountItWillUse(t *testing.T) {
	f := fakeFarEnd{ports: map[int]reach{22: reachOpen}, sshUser: "midna", thisUser: "midna"}
	r, err := planRoute("mac", farEnd{addr: "10.77.0.2"}, f)
	if err != nil {
		t.Fatal(err)
	}
	if r.password != "" {
		t.Errorf("overrode ssh's choice with %q", r.password)
	}
	if !strings.Contains(r.note, "midna") {
		t.Errorf("the note does not say which account: %s", r.note)
	}
}

// A User in somebody's ssh config is theirs, and wins over the owner.
func TestSSHConfigUserWinsOverTheOwner(t *testing.T) {
	f := fakeFarEnd{ports: map[int]reach{22: reachOpen}, sshUser: "admin", thisUser: "midna"}
	r, err := planRoute("mac", farEnd{addr: "10.77.0.2", owner: "huiyunlee"}, f)
	if err != nil {
		t.Fatal(err)
	}
	if r.password != "" || !strings.Contains(r.note, "admin") {
		t.Errorf("password %q, note %q; want ssh config's admin", r.password, r.note)
	}

	f.open = map[string]bool{"22/admin": true, "22/huiyunlee": true}
	r, _ = planRoute("mac", farEnd{addr: "10.77.0.2", owner: "huiyunlee"}, f)
	if got := names(r.accounts); len(got) != 1 || got[0] != "admin" {
		t.Errorf("offered %v, want only the configured account", got)
	}
}

// A key that opens the owner's account logs in there, without a word — that
// is the expected account — and without -l when ssh would send it anyway.
func TestAKeyForTheOwnerLogsInThere(t *testing.T) {
	f := fakeFarEnd{
		ports:    map[int]reach{22: reachOpen},
		open:     map[string]bool{"22/jetson": true},
		sshUser:  "huiyunlee",
		thisUser: "huiyunlee",
	}
	r, err := planRoute("midna", farEnd{addr: "10.77.0.1", owner: "jetson"}, f)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(r.accounts); len(got) != 1 || got[0] != "jetson" || !r.accounts[0].Default {
		t.Fatalf("offered %+v", r.accounts)
	}
	if got, _ := pickAccount("midna", r, f.sshUser); got != "jetson" {
		t.Errorf("logs in as %q", got)
	}

	same := route{accounts: []sshd.Account{{Name: "huiyunlee", Default: true}}}
	if got, _ := pickAccount("midna", same, "huiyunlee"); got != "" {
		t.Errorf("named %q, which ssh sends anyway", got)
	}
}

// The owner first, this person's own name next, root last — and an owner who
// is this person is offered once.
func TestCandidatesAreOfferedInOrderAndOnce(t *testing.T) {
	f := fakeFarEnd{
		ports:    map[int]reach{22: reachOpen},
		open:     map[string]bool{"22/jetson": true, "22/huiyunlee": true, "22/root": true},
		sshUser:  "huiyunlee",
		thisUser: "huiyunlee",
	}
	r, _ := planRoute("midna", farEnd{addr: "10.77.0.1", owner: "jetson"}, f)
	if got := strings.Join(names(r.accounts), ","); got != "jetson,huiyunlee,root" {
		t.Errorf("offered %s", got)
	}

	r, _ = planRoute("midna", farEnd{addr: "10.77.0.1", owner: "huiyunlee"}, f)
	if got := strings.Join(names(r.accounts), ","); got != "huiyunlee,root" {
		t.Errorf("offered %s", got)
	}
}

// makima's own server is asked, and used, when a key opens something there.
func TestTheBuiltInServerIsPreferredWhenItAnswers(t *testing.T) {
	f := fakeFarEnd{
		ports:  map[int]reach{sshd.DefaultPort: reachOpen, 22: reachOpen},
		listed: []sshd.Account{{Name: "jetson", Default: true}},
	}
	r, err := planRoute("midna", farEnd{addr: "10.77.0.1"}, f)
	if err != nil {
		t.Fatal(err)
	}
	if r.port != sshd.DefaultPort || len(r.accounts) != 1 {
		t.Errorf("route %+v", r)
	}

	// An older makima's server cannot list, but a key-only login still works.
	f.listed = nil
	f.open = map[string]bool{"2222/": true}
	r, _ = planRoute("midna", farEnd{addr: "10.77.0.1"}, f)
	if r.port != sshd.DefaultPort {
		t.Errorf("an older makima's server was passed over: %+v", r)
	}
}

// A machine nobody can ssh into says how to change that, rather than leaving
// ssh to print "Connection refused".
func TestNothingListeningSaysHowToFixIt(t *testing.T) {
	f := fakeFarEnd{ports: map[int]reach{sshd.DefaultPort: reachRefused, 22: reachRefused}}
	_, err := planRoute("mac", farEnd{addr: "10.77.0.2"}, f)
	if err == nil || !strings.Contains(err.Error(), "makima sshd -on") || !strings.Contains(err.Error(), "Remote Login") {
		t.Errorf("got %v", err)
	}

	// Only makima's server, which takes no passwords and no key of ours.
	f.ports[sshd.DefaultPort] = reachOpen
	_, err = planRoute("mac", farEnd{addr: "10.77.0.2", owner: "huiyunlee"}, f)
	if err == nil || !strings.Contains(err.Error(), "keys only") || !strings.Contains(err.Error(), "huiyunlee") {
		t.Errorf("got %v", err)
	}
}

// A port that only times out is not proof of anything, and must not stop ssh
// being tried.
func TestSilenceIsNotRefusal(t *testing.T) {
	f := fakeFarEnd{ports: map[int]reach{sshd.DefaultPort: reachUnknown, 22: reachUnknown}, sshUser: "a", thisUser: "a"}
	if _, err := planRoute("mac", farEnd{addr: "10.77.0.2"}, f); err != nil {
		t.Errorf("gave up on an unanswered port: %v", err)
	}
}

// Host keys are filed under the machine, so an address handed to another
// machine is not a host-key warning, and each of a machine's two servers has
// its own entry.
func TestHostKeysAreFiledUnderTheMachine(t *testing.T) {
	priv, _ := key.NewPrivate()
	k := priv.Public()

	a := hostKeyAlias(k, 0)
	if a != hostKeyAlias(k, 22) || !strings.HasPrefix(a, "makima-") || len(a) != len("makima-")+16 {
		t.Errorf("alias %q", a)
	}
	if b := hostKeyAlias(k, sshd.DefaultPort); b != "["+a+"]:2222" {
		t.Errorf("the built-in server's alias is %q", b)
	}
	other, _ := key.NewPrivate()
	if hostKeyAlias(other.Public(), 0) == a {
		t.Error("two machines share an alias")
	}

	x := sshProber{p: farEnd{addr: "10.77.0.1", key: k}}
	opts := strings.Join(x.options(0), " ")
	if !strings.Contains(opts, "HostKeyAlias="+a) || !strings.Contains(opts, "StrictHostKeyChecking=accept-new") ||
		!strings.Contains(opts, "LogLevel=ERROR") {
		t.Errorf("options %q", opts)
	}
	// With no key to go on — an older daemon — ssh's own filing stands.
	if opts := (sshProber{p: farEnd{addr: "10.77.0.1"}}).options(0); len(opts) != 0 {
		t.Errorf("options %q without a key", opts)
	}
}

// An owner that could not be an account's name is not passed to ssh: it
// would arrive as an option, or as terminal control codes.
func TestAnOwnerThatIsNoNameIsDropped(t *testing.T) {
	for _, bad := range []string{"-oProxyCommand=sh", "a b", "root\x1b[2J", ".hidden"} {
		if p := peerFrom(localapi.PeerInfo{Owner: bad}); p.owner != "" {
			t.Errorf("kept owner %q", bad)
		}
	}
	if p := peerFrom(localapi.PeerInfo{Owner: "huiyunlee"}); p.owner != "huiyunlee" {
		t.Errorf("dropped a good owner")
	}
}

// ssh's prompt names the machine by its host-key alias, which reads like an
// ID; what is asked is only whose password it is.
func TestThePasswordPromptNamesOnlyTheAccount(t *testing.T) {
	for in, want := range map[string]string{
		"huiyunlee@makima-3f9a1c0e5b2d7a64's password: ":                        "huiyunlee's password: ",
		"midna@10.77.0.1's password: ":                                          "midna's password: ",
		"(huiyunlee@makima-3f9a1c0e5b2d7a64) Password:":                         "huiyunlee's password: ",
		"(midna@10.77.0.1) Password: ":                                          "midna's password: ",
		"(midna@10.77.0.1) Verification code:":                                  "Verification code: ",
		"Enter passphrase for key '/Users/h/.ssh/id_ed25519': ":                 "Enter passphrase for key '/Users/h/.ssh/id_ed25519': ",
		"Are you sure you want to continue connecting (yes/no/[fingerprint])? ": "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
	} {
		if got := plainPrompt(in); got != want {
			t.Errorf("plainPrompt(%q) = %q, want %q", in, got, want)
		}
	}
}
