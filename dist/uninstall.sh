#!/bin/sh
# uninstall.sh — take makima off this machine, all of it.
#
# Every version's leftovers, not just the current one's: the app and the
# daemons, their launchd or systemd registrations, the network this machine was
# on or held (its keys, the control plane's state, the server's port), the
# logs, the resolver file, the sudoers rule and root's copy of the binaries that
# the app's "don't ask again" created, the app and its data, the `die` alias,
# and the app's privacy grants. Afterwards the machine has never seen makima.
#
# Nothing runs this on your behalf. Installing keeps a machine's state and only
# replaces what runs — see dist/update.sh — because a reinstall is not a reason
# to lose a network. This is for when removing makima is the point.
#
# This machine only. Other machines on the network keep their own state; run
# this on each of them to take them off too.

set -u
[ "$(id -u)" -eq 0 ] || exec sudo sh "$0" "$@"

os=$(uname -s)
say() { printf '  %-7s %s\n' "$1" "$2"; }

# The person behind sudo, for the parts of makima that live in a home directory.
who=${SUDO_USER:-}
home=
uid=
if [ -n "$who" ] && [ "$who" != root ]; then
	uid=$(id -u "$who")
	home=$(eval echo "~$who")
fi
as_user() { [ -n "$uid" ] && launchctl asuser "$uid" sudo -u "$who" "$@"; }

gone() { ! pgrep -x "$1" >/dev/null 2>&1; }

# TERM, up to 20 seconds to exit — the node puts routes back on its way out —
# and KILL for anything still there.
stop_proc() {
	gone "$1" && return 0
	pkill -TERM -x "$1" 2>/dev/null
	i=0
	while ! gone "$1" && [ $i -lt 80 ]; do sleep 0.25; i=$((i + 1)); done
	if ! gone "$1"; then
		say kill "$1"
		pkill -KILL -x "$1" 2>/dev/null
		sleep 0.5
	fi
}

# --- stop -----------------------------------------------------------------

# The app first: it restarts the tunnel when it sees it go, if left running.
if ! gone makima-desktop; then
	say stop "makima app"
	[ "$os" = Darwin ] && as_user osascript -e 'with timeout of 5 seconds' -e 'quit app "makima"' -e 'end timeout' >/dev/null 2>&1
	stop_proc makima-desktop
fi

# The network through makima itself, where a copy is here, so the interface,
# routes, resolver file and firewall rule go back the way the daemon knows how.
# Versions before --all fall back to plain `down`; the server and relay are
# then stopped below.
for m in /usr/local/bin/makima /Library/PrivilegedHelperTools/makima/makima /usr/bin/makima /Applications/makima.app/Contents/MacOS/makima; do
	if [ -x "$m" ]; then
		say stop "the network (makima down)"
		"$m" down --all >/dev/null 2>&1 || "$m" down >/dev/null 2>&1 || true
		break
	fi
done

# Registrations, so nothing is started again at boot or by a supervisor the
# moment it is killed below.
if [ "$os" = Darwin ]; then
	for l in sh.makima.makimad sh.makima.server sh.makima.relay; do
		launchctl bootout "system/$l" >/dev/null 2>&1
	done
	for p in /Library/LaunchDaemons/sh.makima.*.plist; do
		[ -e "$p" ] || continue
		launchctl bootout "system/$(basename "$p" .plist)" >/dev/null 2>&1
		say delete "$p"
		rm -f "$p"
	done
	# The app's start-at-login agent, written by Tauri's autostart plugin
	# under the bare label "makima".
	agent="$home/Library/LaunchAgents/makima.plist"
	if [ -n "$home" ] && [ -f "$agent" ] && grep -q makima-desktop "$agent"; then
		launchctl bootout "gui/$uid/makima" >/dev/null 2>&1
		say delete "$agent"
		rm -f "$agent"
	fi
elif command -v systemctl >/dev/null 2>&1; then
	for u in makimad makima-server makima-relay; do
		systemctl disable --now "$u" >/dev/null 2>&1
		if [ -f "/etc/systemd/system/$u.service" ]; then
			say delete "/etc/systemd/system/$u.service"
			rm -f "/etc/systemd/system/$u.service"
		fi
	done
	systemctl daemon-reload 2>/dev/null
	systemctl reset-failed makimad makima-server makima-relay >/dev/null 2>&1
fi

# Whatever is left was started by hand, or by a version that did not know how
# to stop it.
for n in makimad makima-server makima-relay makima; do
	gone "$n" && continue
	say stop "$n (pid $(pgrep -x "$n" | tr '\n' ' ' | sed 's/ $//'))"
	stop_proc "$n"
done

# The holes makima made in a bare nftables or iptables ruleset: each rule is
# tagged with a comment beginning "makima ", which is how only makima's are
# taken out. firewalld and ufw ports are left — makima cannot tell its port
# from the same one opened for something else.
if [ "$os" = Linux ]; then
	if command -v nft >/dev/null 2>&1; then
		nft -a list ruleset 2>/dev/null | awk '
			$1 == "table" { fam = $2; tbl = $3 }
			$1 == "chain" { ch = $2 }
			/comment "makima / { print fam, tbl, ch, $NF }
		' | while read -r fam tbl ch h; do
			nft delete rule "$fam" "$tbl" "$ch" handle "$h" 2>/dev/null && say delete "nftables rule $h in $fam $tbl $ch"
		done
	fi
	if command -v iptables >/dev/null 2>&1; then
		iptables -S INPUT 2>/dev/null | grep -- '--comment "makima ' | sed 's/^-A /-D /' | while IFS= read -r rule; do
			eval "iptables $rule" 2>/dev/null && say delete "iptables rule: $rule"
		done
	fi
fi

# --- delete ---------------------------------------------------------------

# The network's keys and the control plane's state are copied aside first, so
# an uninstall run by mistake on the machine holding a network can be undone
# until /tmp is next cleared. Deleting them is the point; losing a network
# nobody meant to lose is not.
kept=
for d in /etc/makima /var/lib/makima ${home:+"$home/.config/makima"}; do
	[ -n "$(ls -A "$d" 2>/dev/null)" ] || continue
	if [ -z "$kept" ]; then
		kept=/tmp/makima-uninstalled-$(date +%Y%m%d-%H%M%S)
		mkdir -m 700 "$kept"
	fi
	mkdir -p "$kept$(dirname "$d")" && cp -Rp "$d" "$kept$d"
done
held=
[ -f /var/lib/makima/control.json ] && held=1

# The app. Its package, on Linux, owns /usr/lib/makima; removing the package is
# what takes that away cleanly.
if [ "$os" = Darwin ]; then
	if [ -d /Applications/makima.app ]; then
		say delete /Applications/makima.app
		rm -rf /Applications/makima.app
	fi
else
	if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' makima 2>/dev/null | grep -q 'ok installed'; then
		say delete "the makima package (dpkg)"
		dpkg -r makima >/dev/null
	elif command -v rpm >/dev/null 2>&1 && rpm -q makima >/dev/null 2>&1; then
		say delete "the makima package (rpm)"
		rpm -e makima >/dev/null
	fi
fi

for p in /etc/makima /var/lib/makima /var/log/makima \
	/Library/PrivilegedHelperTools/makima /usr/local/share/makima /usr/lib/makima \
	/usr/local/bin/makima /usr/local/bin/makimad /usr/local/bin/makima-server \
	/usr/local/bin/makima-relay /usr/local/bin/makima-desktop \
	/etc/sudoers.d/makima_*; do
	[ -e "$p" ] || [ -L "$p" ] || continue
	say delete "$p"
	rm -rf "$p"
done

# Only the resolver files makima wrote: they say so on their first line.
for f in /etc/resolver/*; do
	if grep -qs '^# Managed by makima' "$f"; then
		say delete "$f"
		rm -f "$f"
	fi
done

# The person's own: the app's data, the operator signing key, the `die` alias.
if [ -n "$home" ]; then
	if [ "$os" = Darwin ]; then
		as_user defaults delete sh.makima.desktop >/dev/null 2>&1
		rels='Library/Application Support/sh.makima.desktop
Library/Caches/sh.makima.desktop
Library/WebKit/sh.makima.desktop
Library/WebKit/makima-desktop
Library/HTTPStorages/sh.makima.desktop
Library/Saved Application State/sh.makima.desktop.savedState
Library/Preferences/sh.makima.desktop.plist
Library/Logs/sh.makima.desktop'
	else
		rels='.config/sh.makima.desktop
.local/share/sh.makima.desktop
.cache/sh.makima.desktop
.config/autostart/makima.desktop'
	fi
	printf '%s\n.config/makima\n' "$rels" | while IFS= read -r rel; do
		[ -e "$home/$rel" ] || continue
		say delete '~'"/$rel"
		rm -rf "${home:?}/$rel"
	done

	# The block `makima up` appended, and the blank line it put before it.
	for rc in .zshrc .bashrc .bash_profile .profile; do
		f="$home/$rc"
		grep -qsxF '# >>> makima >>>' "$f" || continue
		say edit '~'"/$rc (the die alias)"
		t=$(mktemp) || continue
		awk '
			$0 == "# >>> makima >>>" { skip = 1; if (held && prev == "") held = 0 }
			!skip { if (held) print prev; prev = $0; held = 1 }
			$0 == "# <<< makima <<<" { skip = 0 }
			END { if (held) print prev }
		' "$f" >"$t" && cat "$t" >"$f"
		rm -f "$t"
	done
fi

# Privacy grants belong to the binary that was granted them, and a rebuilt app
# is a different binary; a stale entry left in System Settings looks enabled and
# is not. System Settings caches the table, so it is closed first.
if [ "$os" = Darwin ] && [ -n "$uid" ]; then
	gone "System Settings" || as_user osascript -e 'quit app "System Settings"' >/dev/null 2>&1
	as_user tccutil reset All sh.makima.desktop >/dev/null 2>&1
fi

say gone "makima is off this machine"
if [ -n "$kept" ]; then
	say kept "the old network's keys and state, in $kept (root only), until /tmp is cleared"
fi
if [ -n "$held" ]; then
	say note "this machine held a network; the machines on it are now on a network with no server"
fi
exit 0
