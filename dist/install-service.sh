#!/bin/sh
# Install makima as a service that survives a reboot.
#
# Separate from `make` on purpose. Enabling a daemon at boot on a machine
# somebody was only trying out is a surprise, and this one takes over a network
# interface and edits the routing table. It should be asked for.
set -eu

die() { echo "install-service: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run this with sudo"

DIR=$(cd "$(dirname "$0")" && pwd)

case "$(uname -s)" in
Linux)
	command -v systemctl >/dev/null 2>&1 || die "no systemctl; install the unit in $DIR by hand"

	# Only the node daemon by default. The control plane and relay belong on
	# specific machines, not on every machine that installs makima.
	install -m 0644 "$DIR/makimad.service" /etc/systemd/system/makimad.service
	systemctl daemon-reload
	systemctl enable --now makimad.service

	echo "  makimad enabled and started"
	echo
	echo "  status:  systemctl status makimad"
	echo "  logs:    journalctl -u makimad -f"
	echo
	echo "  the control plane and relay have their own units, for the machines"
	echo "  that run them:"
	echo "    install -m 0644 $DIR/makima-server.service /etc/systemd/system/"
	echo "    install -m 0644 $DIR/makima-relay.service  /etc/systemd/system/"
	;;

Darwin)
	PLIST=/Library/LaunchDaemons/sh.makima.makimad.plist
	install -m 0644 "$DIR/sh.makima.makimad.plist" "$PLIST"

	# bootout first so re-running this is an upgrade rather than an error. The
	# failure is ignored because there is legitimately nothing loaded the first
	# time.
	launchctl bootout system "$PLIST" 2>/dev/null || true
	launchctl bootstrap system "$PLIST"

	echo "  makimad loaded and started"
	echo
	echo "  logs:  tail -f /var/log/makimad.log"
	echo "  stop:  sudo launchctl bootout system $PLIST"
	;;

*)
	die "no service definition for $(uname -s); run 'makimad' yourself"
	;;
esac
