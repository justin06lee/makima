package migrate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// AuthorizeScript adds the public keys on stdin to this account's
// authorized_keys, each once, and says how many were new.
//
// Run as the account the migration logs in as — not root — so the file and its
// directory stay owned by the person who will use them. It is what keeps
// ordinary `ssh` working on a machine that was reached through Tailscale SSH,
// which needs no keys at all and goes when Tailscale does. A file that does
// not end in a newline gets one first, or the first key added would be glued
// to the last one there.
const AuthorizeScript = `umask 077
f="$HOME/.ssh/authorized_keys"
mkdir -p "$HOME/.ssh" && touch "$f" || exit 1
chmod 700 "$HOME/.ssh"; chmod 600 "$f"
[ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ] && echo >> "$f"
n=0
while IFS= read -r k; do
  [ -n "$k" ] || continue
  grep -qxF -- "$k" "$f" && continue
  printf '%s\n' "$k" >> "$f" && n=$((n+1))
done
command -v restorecon >/dev/null 2>&1 && restorecon -R "$HOME/.ssh" >/dev/null 2>&1
echo "added=$n"
`

// CheckScript is run on a machine to prove a login reached it.
const CheckScript = "echo makima-ok"

// Keys are this person's SSH keys, sorted by whether a login with nobody there
// to type a passphrase can use them — which is every login the migration makes.
type Keys struct {
	// Public is the public half of each key that can: one the agent holds,
	// or a key file with no passphrase. One per line.
	Public string

	// Files are the private key files among those. ssh is handed them by
	// name, because on its own it only tries a few default names.
	Files []string

	// Locked are key files that need a passphrase no agent holds. A login
	// that offers one is refused, however right the key is.
	Locked []string
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
		line := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
		f := strings.Fields(line)
		if len(f) < 2 || !isKeyType(f[0]) || seen[f[1]] {
			continue // not a key, or one the agent already signs with
		}
		priv := strings.TrimSuffix(m, ".pub")
		if _, err := os.Stat(priv); err != nil {
			continue
		}
		if !opensWithoutPassphrase(priv) {
			k.Locked = append(k.Locked, priv)
			continue
		}
		if add(line) {
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
