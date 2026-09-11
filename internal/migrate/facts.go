package migrate

import (
	"bufio"
	"fmt"
	"net/netip"
	"strings"
)

// ProbeScript is what a machine is asked before anything is done to it.
//
// Plain POSIX shell, because makima is not on the machine yet — finding out
// whether it can be put there is the point. It changes nothing: every line
// only reads, and `sudo -n true` asks sudo whether it would need a password
// without ever prompting for one. The answers come back as key=value lines,
// which survive any login shell's noise better than anything structured.
const ProbeScript = `exec 2>/dev/null
PATH=$PATH:/usr/local/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/run/current-system/sw/bin
echo "os=$(uname -s)"
echo "arch=$(uname -m)"
echo "uid=$(id -u)"
echo "user=$(id -un)"
echo "hostname=$(hostname)"
if [ "$(id -u)" = 0 ]; then echo sudo=root
elif ! command -v sudo >/dev/null; then echo sudo=none
elif sudo -n true </dev/null >/dev/null 2>&1; then echo sudo=nopasswd
else echo sudo=password; fi
m=$(command -v makima)
[ -n "$m" ] && echo "makima=$("$m" version)"
if [ -e /Library/LaunchDaemons/sh.makima.makimad.plist ] || [ -e /etc/systemd/system/makimad.service ]; then echo member=1; fi
if [ -e /Library/LaunchDaemons/sh.makima.server.plist ] || [ -e /etc/systemd/system/makima-server.service ]; then echo holds=1; fi
t=$(command -v tailscale)
[ -z "$t" ] && [ -x /Applications/Tailscale.app/Contents/MacOS/Tailscale ] && t=/Applications/Tailscale.app/Contents/MacOS/Tailscale
echo "tailscale=$t"
p=$PPID
for i in 1 2 3 4 5; do
  c=$(ps -o comm= -p "$p" | tr -d ' ')
  case "$c" in *tailscaled*) echo via=tailscale; break ;; *sshd*) echo via=openssh; break ;; esac
  p=$(ps -o ppid= -p "$p" | tr -d ' ')
  [ -z "$p" ] || [ "$p" = 1 ] && break
done
if [ "$(uname -s)" = Darwin ]; then
  echo init=launchd
  netstat -anp tcp | grep LISTEN | grep -qE '[.:]22 ' && echo openssh=1
  ifconfig | awk '/inet6? /{print "addr=" $2}'
  i=$(route -n get 1.1.1.1 | awk '/interface:/{print $2}')
  [ -n "$i" ] && echo "route=$(ipconfig getifaddr "$i")"
  [ -d /Applications/Tailscale.app ] && echo pkg=app
  [ -z "$t" ] || [ -d /Applications/Tailscale.app ] || echo pkg=daemon
else
  if [ -d /run/systemd/system ]; then echo init=systemd; elif command -v rc-service >/dev/null; then echo init=openrc; else echo init=other; fi
  if command -v ss >/dev/null; then ss -Hltn | awk '{print $4}' | grep -qE '[:.]22$' && echo openssh=1; fi
  ip -o addr show scope global | awk '{split($4,a,"/"); print "addr=" a[1]}'
  echo "route=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')"
  if [ -e /etc/NIXOS ]; then echo pkg=nix
  elif command -v pacman >/dev/null && pacman -Qq tailscale >/dev/null; then echo pkg=pacman
  elif command -v dpkg-query >/dev/null && dpkg-query -W tailscale >/dev/null; then echo pkg=apt
  elif command -v rpm >/dev/null && rpm -q tailscale >/dev/null; then echo pkg=rpm
  elif command -v apk >/dev/null && apk info -e tailscale >/dev/null; then echo pkg=apk
  elif command -v snap >/dev/null && snap list tailscale >/dev/null; then echo pkg=snap
  elif [ -n "$t" ]; then echo pkg=manual; fi
fi
echo done=1
`

// Facts is what the probe found.
type Facts struct {
	OS       string `json:"os"`   // linux or darwin, as Go spells it
	Arch     string `json:"arch"` // amd64, arm64 or arm
	User     string `json:"user"`
	Hostname string `json:"hostname,omitempty"`

	// Sudo is how this account becomes root: "root" (it is), "nopasswd",
	// "password", or "none".
	Sudo string `json:"sudo"`

	Makima string `json:"makima,omitempty"` // installed version, if any
	Member bool   `json:"member,omitempty"` // on a makima network already
	Holds  bool   `json:"holds,omitempty"`  // holds one

	Tailscale string `json:"tailscale,omitempty"` // the CLI's path
	Pkg       string `json:"pkg,omitempty"`       // how Tailscale was installed

	// Via is what the probe's own SSH session came in through. "tailscale"
	// means Tailscale SSH — and that once Tailscale is gone, nothing may be
	// listening for SSH at all unless OpenSSH is too.
	Via     string `json:"via,omitempty"`
	OpenSSH bool   `json:"openssh,omitempty"`

	Init  string       `json:"init,omitempty"`
	Addrs []netip.Addr `json:"addrs,omitempty"`
	Route netip.Addr   `json:"route,omitempty"` // source address toward the internet
}

// ParseFacts reads what ProbeScript printed.
func ParseFacts(out string) (Facts, error) {
	var f Facts
	complete := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "os":
			f.OS = goos(v)
		case "arch":
			f.Arch = goarch(v)
		case "user":
			f.User = v
		case "hostname":
			f.Hostname = v
		case "sudo":
			f.Sudo = v
		case "makima":
			f.Makima = v
		case "member":
			f.Member = v == "1"
		case "holds":
			f.Holds = v == "1"
		case "tailscale":
			f.Tailscale = v
		case "pkg":
			if f.Pkg == "" {
				f.Pkg = v
			}
		case "via":
			f.Via = v
		case "openssh":
			f.OpenSSH = v == "1"
		case "init":
			f.Init = v
		case "addr":
			// ifconfig prints scoped link-local addresses as fe80::1%en0.
			v, _, _ = strings.Cut(v, "%")
			if a, err := netip.ParseAddr(v); err == nil {
				f.Addrs = append(f.Addrs, a)
			}
		case "route":
			if a, err := netip.ParseAddr(v); err == nil {
				f.Route = a
			}
		case "done":
			complete = true
		}
	}
	if !complete || f.OS == "" {
		return f, fmt.Errorf("the machine did not answer the probe — its login shell may print something odd, or it is not a Unix machine")
	}
	return f, nil
}

func goos(uname string) string {
	switch strings.ToLower(uname) {
	case "linux":
		return "linux"
	case "darwin":
		return "darwin"
	}
	return strings.ToLower(uname)
}

func goarch(uname string) string {
	switch uname {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l", "armv6l", "armv7", "arm":
		return "arm"
	}
	return uname
}

// Supported says whether a build of makima exists for this machine.
func (f Facts) Supported() bool {
	switch f.OS + "/" + f.Arch {
	case "linux/amd64", "linux/arm64", "linux/arm", "darwin/amd64", "darwin/arm64":
		return true
	}
	return false
}

// Public is an address on one of the machine's own interfaces that the whole
// internet can reach, if it has one: the defining feature of a VPS, and the
// one thing that makes a machine able to hold a network for devices anywhere.
func (f Facts) Public() netip.Addr {
	for _, a := range f.Addrs {
		if a.Is4() && isPublic(a) {
			return a
		}
	}
	return netip.Addr{}
}

// Reach is the address other machines would use to find this one, were it to
// hold the network: a public address if it has one, otherwise the one it uses
// to reach the internet, which on a home network is its LAN address.
func (f Facts) Reach() netip.Addr {
	if a := f.Public(); a.IsValid() {
		return a
	}
	if f.Route.IsValid() && !IsTailscaleAddr(f.Route) {
		return f.Route
	}
	for _, a := range f.Addrs {
		if a.Is4() && a.IsPrivate() && !IsTailscaleAddr(a) {
			return a
		}
	}
	return netip.Addr{}
}

func isPublic(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !IsTailscaleAddr(a) && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}
