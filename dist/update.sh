#!/bin/sh
# update.sh — take makima's running pieces down for a new build, and put back
# exactly what was there.
#
#   sh dist/update.sh stop     stop what is running, and write down what it was
#   sh dist/update.sh start     start again exactly that
#
# It never touches state. Not the network this machine is on or holds, not its
# keys, not the app's data, not the launchd or systemd registrations — only the
# processes, and only for as long as it takes to replace the binaries they run.
#
# That is the whole difference from uninstall.sh, which exists to remove
# makima and does remove all of it. An install used to run *that* first, so
# every `make install` was a new machine: the mesh forgotten, the invites spent,
# the machine holding a network no longer holding it. Nobody wants a reinstall
# to cost them their network.
#
# What was running is written to a state directory on the way down and read
# back on the way up. "Exactly what was stopped" is the point: up to three
# daemons can be running — the node, and on the machine holding the mesh its
# server and its relay — and a node that was deliberately down stays down.

set -u
[ "$(id -u)" -eq 0 ] || exec sudo sh "$0" "$@"

STATE=/var/tmp/makima-update
LABELS="sh.makima.makimad sh.makima.server sh.makima.relay"
UNITS="makimad makima-server makima-relay"
BINS="makimad makima-server makima-relay"
APP=/Applications/makima.app

os=$(uname -s)
say() { printf '  %-7s %s\n' "$1" "$2"; }

who=${SUDO_USER:-}
uid=
if [ -n "$who" ] && [ "$who" != root ]; then uid=$(id -u "$who" 2>/dev/null); fi
as_user() { [ -n "$uid" ] && launchctl asuser "$uid" sudo -u "$who" "$@"; }

gone() { ! pgrep -x "$1" >/dev/null 2>&1; }

# TERM, up to 20 seconds — the node puts routes and the resolver back on its
# way out — then KILL for anything still there.
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

stop() {
	rm -rf "$STATE"
	mkdir -p "$STATE" && chmod 700 "$STATE"

	# The app first: left running, it brings the tunnel back up underneath the
	# replacement it is waiting for.
	if ! gone makima-desktop; then
		say stop "the makima app"
		touch "$STATE/app"
		[ "$os" = Darwin ] && as_user osascript -e 'with timeout of 5 seconds' -e 'quit app "makima"' -e 'end timeout' >/dev/null 2>&1
		stop_proc makima-desktop
	fi

	# Service managers before anything else: a process killed out from under
	# one is started straight back up on the old binary. bootout and stop both
	# send SIGTERM, so the node still tidies up after itself — and the
	# definition stays on disk, which is what makes starting it again possible.
	if [ "$os" = Darwin ]; then
		for l in $LABELS; do
			if launchctl print "system/$l" >/dev/null 2>&1; then
				say stop "$l"
				echo "$l" >> "$STATE/launchd"
				launchctl bootout "system/$l" >/dev/null 2>&1
			fi
		done
	elif command -v systemctl >/dev/null 2>&1; then
		for u in $UNITS; do
			if systemctl is-active --quiet "$u" 2>/dev/null; then
				say stop "$u"
				echo "$u" >> "$STATE/systemd"
				systemctl stop "$u" >/dev/null 2>&1
			fi
		done
	fi

	# Whatever is left was started by hand. Its command line is kept so it can
	# be started the same way.
	for b in $BINS; do
		gone "$b" && continue
		for pid in $(pgrep -x "$b"); do
			say stop "$b (pid $pid)"
			printf '%s\n' "$(ps -o args= -p "$pid")" >> "$STATE/spawned"
		done
		stop_proc "$b"
	done

	# A rule written by an older app, which granted more than the app now asks
	# for: `makima join *` and friends, with no password, to anything running
	# as that person. The binaries it points at are about to be replaced with
	# ones that no longer want it, so it goes now rather than lingering until
	# the app happens to rewrite it.
	for f in /etc/sudoers.d/makima_*; do
		[ -e "$f" ] || continue
		if grep -q '\*' "$f" 2>/dev/null; then
			say delete "$f (an old rule with wildcards in it)"
			rm -f "$f"
		fi
	done
}

start() {
	[ -d "$STATE" ] || return 0

	if [ -f "$STATE/launchd" ]; then
		while read -r l; do
			say start "$l"
			launchctl bootstrap system "/Library/LaunchDaemons/$l.plist" >/dev/null 2>&1 ||
				say note "$l did not start — see /var/log/makima/"
		done < "$STATE/launchd"
	fi

	if [ -f "$STATE/systemd" ]; then
		while read -r u; do
			say start "$u"
			systemctl start "$u" >/dev/null 2>&1 || say note "$u did not start — journalctl -u $u"
		done < "$STATE/systemd"
	fi

	if [ -f "$STATE/spawned" ]; then
		# Somewhere to put the output. A daemon started here has no terminal,
		# and a silent failure is the worst kind — so if the usual place cannot
		# be made, anywhere is better than losing what it said.
		logdir=/var/log/makima
		mkdir -p "$logdir" 2>/dev/null
		[ -w "$logdir" ] || logdir=${TMPDIR:-/tmp}

		while read -r args; do
			[ -n "$args" ] || continue
			name=$(basename "$(echo "$args" | cut -d' ' -f1)")
			say start "$name"
			# shellcheck disable=SC2086
			nohup $args >> "$logdir/$name.log" 2>&1 &
		done < "$STATE/spawned"
	fi

	if [ -f "$STATE/app" ]; then
		say start "the makima app"
		if [ "$os" = Darwin ]; then
			as_user open "$APP" >/dev/null 2>&1
		else
			as_user sh -c 'setsid makima-desktop >/dev/null 2>&1 &'
		fi
	fi

	rm -rf "$STATE"
}

case "${1:-}" in
stop) stop ;;
start) start ;;
*)
	echo "usage: $0 stop|start" >&2
	exit 2
	;;
esac
