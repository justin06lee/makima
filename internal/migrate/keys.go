package migrate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/justin06lee/makima/internal/hostaddr"
)

// TempKeyComment ends the line of the move's temporary key in every
// authorized_keys it goes into. It is how the key is found again to be taken
// out — by the run that put it there, or, if that one died half way, the next.
const TempKeyComment = "makima-move-temporary"

// AuthorizeScript adds the public keys on stdin to an account's
// authorized_keys, each once, and says whose file it was and how many were
// new.
//
// The account is the one it runs as — or, run as root with a name as $1, that
// account, if the machine has it: the move logs in as root wherever Tailscale
// SSH lets it, and the person's own keys belong in their own account. Written
// by the account itself wherever it can be, so the file and directory stay
// owned by the person who will use them; where root writes them, they are
// handed over. A symlinked file or directory is refused rather than followed,
// and a file that does not end in a newline gets one first, or the first key
// added would be glued to the last one there.
const AuthorizeScript = `umask 077
u=$(id -un)
h=$HOME
if [ -n "$1" ] && [ "$1" != "$u" ] && [ "$(id -u)" = 0 ] && id -u "$1" >/dev/null 2>&1; then
  u=$1
  h=$(getent passwd "$u" 2>/dev/null | cut -d: -f6)
  [ -n "$h" ] || h=$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
fi
[ -n "$h" ] && [ -d "$h" ] || exit 1
d="$h/.ssh"
f="$d/authorized_keys"
if [ -L "$d" ] || [ -L "$f" ]; then echo "$f is a symlink, so it was left alone" >&2; exit 1; fi
mkdir -p "$d" && touch "$f" || exit 1
chmod 700 "$d"; chmod 600 "$f"
[ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ] && echo >> "$f"
n=0
while IFS= read -r k; do
  [ -n "$k" ] || continue
  grep -qxF -- "$k" "$f" && continue
  printf '%s\n' "$k" >> "$f" && n=$((n+1))
done
[ "$u" = "$(id -un)" ] || chown "$u:$(id -gn "$u")" "$d" "$f"
command -v restorecon >/dev/null 2>&1 && restorecon -R "$d" >/dev/null 2>&1
echo "as=$u"
echo "added=$n"
`

// RevokeScript takes the move's temporary keys out of this account's
// authorized_keys, and leaves every other line as it was.
const RevokeScript = `f="$HOME/.ssh/authorized_keys"
if [ -f "$f" ] && [ ! -L "$f" ]; then
  t=$(mktemp "$f.XXXXXX") || exit 1
  grep -v -- ' ` + TempKeyComment + `$' "$f" > "$t"
  [ $? -le 1 ] || { rm -f "$t"; exit 1; }
  chmod 600 "$t" && mv "$t" "$f" || { rm -f "$t"; exit 1; }
  command -v restorecon >/dev/null 2>&1 && restorecon "$f" >/dev/null 2>&1
fi
echo revoked
`

// CheckScript is run on a machine to prove a login reached it.
const CheckScript = "echo makima-ok"

// tempLine is the authorized_keys line for the move's temporary key: good
// only from makima's own addresses, and for running commands, nothing more.
func tempLine(pub string) string {
	return `from="` + hostaddr.MeshRange.String() + `",no-agent-forwarding,no-port-forwarding,no-X11-forwarding ` + pub
}

// WithoutTempKeys is an authorized_keys file with the move's temporary keys
// taken out.
func WithoutTempKeys(text string) string {
	var kept []string
	for _, l := range strings.SplitAfter(text, "\n") {
		if strings.HasSuffix(strings.TrimSpace(l), " "+TempKeyComment) {
			continue
		}
		kept = append(kept, l)
	}
	return strings.Join(kept, "")
}

// Keys are this person's SSH keys.
type Keys struct {
	// Public is the public half of each: the ones the agent holds, and each
	// key file in ~/.ssh. One per line. These are what they log in with once
	// Tailscale SSH is gone, typing a passphrase if the key has one.
	Public string

	// Files are the key files that open without a passphrase. ssh is handed
	// them by name, because on its own it only tries a few default names.
	Files []string
}

// FindKeys looks in the person's agent and ~/.ssh.
func FindKeys() Keys {
	agent := ""
	if out, err := exec.Command("ssh-add", "-L").Output(); err == nil {
		agent = string(out)
	}
	home, _ := os.UserHomeDir()
	return findKeys(agent, filepath.Join(home, ".ssh"))
}

func findKeys(agent, dir string) Keys {
	var k Keys
	var public []string
	seen := map[string]bool{}
	add := func(line string) bool {
		f := strings.Fields(line)
		if len(f) < 2 || seen[f[1]] || !isKeyType(f[0]) {
			return false
		}
		seen[f[1]] = true
		public = append(public, strings.TrimSpace(line))
		return true
	}
	for _, l := range strings.Split(agent, "\n") {
		add(l)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.pub"))
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		priv := strings.TrimSuffix(m, ".pub")
		if _, err := os.Stat(priv); err != nil {
			continue
		}
		line := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
		if add(line) && opensWithoutPassphrase(priv) {
			k.Files = append(k.Files, priv)
		}
	}
	k.Public = strings.Join(public, "\n")
	return k
}

func isKeyType(t string) bool {
	return strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") || strings.HasPrefix(t, "sk-")
}

// opensWithoutPassphrase says a private key file can sign with no one there
// to unlock it.
func opensWithoutPassphrase(priv string) bool {
	return exec.Command("ssh-keygen", "-y", "-P", "", "-f", priv).Run() == nil
}
