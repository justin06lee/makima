package migrate

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
