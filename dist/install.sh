#!/bin/sh
# Install makima from a published release.
#
#   curl -fsSL https://raw.githubusercontent.com/justin06lee/makima/master/dist/install.sh | sh
#
# This script exists because `make` from source is the single biggest barrier
# to anybody actually using makima, and no amount of CLI polish fixes it.
# Somebody who has to install Go before they can find out whether a VPN works
# will not find out whether a VPN works.
#
# It downloads the archive for this machine and, where there is a desktop to
# put it on, the app; verifies both against the release's published
# SHA256SUMS; and puts them in place — four binaries in /usr/local/bin, and the
# app in /Applications on a Mac or through apt on Debian and Ubuntu. Nothing is
# enabled at boot and no network configuration is touched: `makima up` does
# that, when it is asked to. Run again over an install, it is an update, and
# what was running is stopped for the replacement and started again, the way
# `make` does it.
#
#   MAKIMA_APP=0        the binaries only, even on a desktop
#   MAKIMA_APP=1        the app as well, even where no desktop is in sight
#   MAKIMA_VERSION      a release other than the latest, by its tag
#   MAKIMA_BINDIR       somewhere other than /usr/local/bin for the binaries
set -eu

REPO=${MAKIMA_REPO:-justin06lee/makima}
VERSION=${MAKIMA_VERSION:-latest}
BINDIR=${MAKIMA_BINDIR:-/usr/local/bin}
APP=${MAKIMA_APP:-auto}
BINS="makima makimad makima-server makima-relay"

die() { echo "install: $*" >&2; exit 1; }
say() { echo "  $*"; }

need() { command -v "$1" >/dev/null 2>&1 || die "this needs $1"; }

as_root() {
	if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
}

# --- what are we on -------------------------------------------------------

os=$(uname -s)
case "$os" in
Darwin) os=darwin ;;
Linux)  os=linux ;;
*)      die "no published build for $os — build from source: https://github.com/$REPO" ;;
esac

arch=$(uname -m)
case "$arch" in
x86_64|amd64)  arch=amd64 ;;
arm64|aarch64) arch=arm64 ;;
armv7l|armv6l) arch=arm ;;
*)             die "no published build for $arch — build from source: https://github.com/$REPO" ;;
esac

need curl
need tar

# --- which release --------------------------------------------------------

if [ "$VERSION" = latest ]; then
	# The redirect target of /releases/latest names the tag, which avoids
	# needing the API and the rate limit that comes with it.
	VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
		"https://github.com/$REPO/releases/latest" | sed 's|.*/tag/||')
	[ -n "$VERSION" ] || die "could not work out the latest version"
fi

base="https://github.com/$REPO/releases/download/$VERSION"
name="makima-$VERSION-$os-$arch"

say "makima $VERSION for $os/$arch"

# --- which app ------------------------------------------------------------

# The app goes where there is a desktop to put it on: every Mac, and a Linux
# machine with a screen in use or one that boots to a graphical login — a
# Jetson set up over SSH has no $DISPLAY in that shell, and still has a
# desktop. A server gets the binaries alone, rather than a web view and GTK it
# would never draw.
want_app() {
	case "$APP" in
	0|no|false) return 1 ;;
	1|yes|true) return 0 ;;
	esac
	[ "$os" = darwin ] && return 0
	[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && return 0
	[ "$(systemctl get-default 2>/dev/null)" = graphical.target ]
}

app=
if want_app; then
	if [ "$os" = darwin ]; then
		app="makima-desktop-$VERSION-$os-$arch.tar.gz"
	elif command -v apt-get >/dev/null 2>&1; then
		app="makima-desktop-$VERSION-$os-$arch.deb"
	else
		say "no app: a release carries it for Debian and Ubuntu only; it builds from source elsewhere"
	fi
fi

# --- download and verify --------------------------------------------------

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading"
curl -fsSL "$base/$name.tar.gz" -o "$tmp/$name.tar.gz" ||
	die "no build published for $os/$arch at $VERSION"

# Checked, not assumed. A binary that is about to be run as root and handed a
# network interface is exactly the wrong thing to take on trust from a CDN.
#
# Every way this can fail is a refusal, not a warning. A verification step that
# prints "skipping" and carries on is not a verification step: the three ways
# it used to give up — no checksums published, no tool to run them with, no
# line for this platform — are each exactly what an attacker who could serve a
# modified archive would arrange. MAKIMA_SKIP_CHECKSUM is there for somebody
# building their own archives, and says what it is.
#
# What this does *not* prove is who built the archive: the tarball and the sums
# come from the same place over the same connection, so this catches a corrupt
# download and a mismatched build, not a compromised release. Signing is the
# answer to that and is not done yet — see the release notes.
if [ -n "${MAKIMA_SKIP_CHECKSUM:-}" ]; then
	say "MAKIMA_SKIP_CHECKSUM is set; not verifying this download"
else
	curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" ||
		die "no SHA256SUMS published for $VERSION, so this download cannot be verified.
  Set MAKIMA_SKIP_CHECKSUM=1 to install anyway."

	if command -v sha256sum >/dev/null 2>&1; then
		sha256() { sha256sum "$1" | cut -d' ' -f1; }
	elif command -v shasum >/dev/null 2>&1; then
		sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
	else
		die "no sha256sum or shasum on this machine, so this download cannot be verified.
  Install one, or set MAKIMA_SKIP_CHECKSUM=1 to install anyway."
	fi
fi

# verify FILE: the file in $tmp against its line in SHA256SUMS.
verify() {
	[ -n "${MAKIMA_SKIP_CHECKSUM:-}" ] && return 0
	want=$(grep " $1\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
	[ -n "$want" ] ||
		die "SHA256SUMS has no line for $1, so this download cannot be verified.
  Set MAKIMA_SKIP_CHECKSUM=1 to install anyway."
	got=$(sha256 "$tmp/$1")
	[ "$want" = "$got" ] || die "checksum mismatch for $1 — refusing to install
  expected $want
  got      $got"
}

verify "$name.tar.gz"
tar -xzf "$tmp/$name.tar.gz" -C "$tmp"

# The app is fetched before anything is stopped, like everything else, so a
# download that fails leaves the machine as it was. A release from before the
# app was published, or with none for this platform, has no line for it in
# SHA256SUMS — that is the binaries alone, said so, rather than a refusal.
if [ -n "$app" ]; then
	if [ -z "${MAKIMA_SKIP_CHECKSUM:-}" ] && ! grep -q " $app\$" "$tmp/SHA256SUMS"; then
		say "no app in $VERSION for $os/$arch; the binaries alone"
		app=
	elif ! curl -fsSL "$base/$app" -o "$tmp/$app"; then
		say "no app in $VERSION for $os/$arch; the binaries alone"
		app=
	else
		verify "$app"
	fi
fi
[ -n "${MAKIMA_SKIP_CHECKSUM:-}" ] || say "checksum ok"

# --- put it in place ------------------------------------------------------

sudo=""
if [ ! -w "$BINDIR" ]; then
	command -v sudo >/dev/null 2>&1 || die "$BINDIR is not writable and there is no sudo"
	sudo=sudo
	say "installing to $BINDIR (needs sudo)"
else
	say "installing to $BINDIR"
fi

# Over an install already here, what is running is stopped for the
# replacement and started again after it: dist/update.sh, which comes in the
# archive, is the whole of that and touches no state. Not for a copy put
# somewhere of somebody's own choosing, which nothing runs from.
updater=
if [ "$BINDIR" = /usr/local/bin ] && [ -f "$tmp/$name/update.sh" ] &&
	{ [ -e "$BINDIR/makimad" ] || [ -d /Applications/makima.app ] || command -v makima-desktop >/dev/null 2>&1; }; then
	updater="$tmp/$name/update.sh"
fi

TRUSTED=/Library/PrivilegedHelperTools/makima

# The Mac's app goes where apps go, over whatever was there. The rest
# follows the Makefile's app-place, reset-permissions and trusted-copy.
place_mac_app() {
	had=
	[ -d /Applications/makima.app ] && had=1
	asudo=
	[ -w /Applications ] || asudo=sudo
	say "installing /Applications/makima.app"
	$asudo rm -rf /Applications/makima.app || return 1
	$asudo tar --no-same-owner -xzf "$tmp/$app" -C /Applications || return 1

	# macOS ties a privacy grant to the binary it was given to, so the app
	# just replaced leaves a stale one behind that looks enabled and is not.
	if [ -n "$had" ]; then
		osascript -e 'quit app "System Settings"' >/dev/null 2>&1 || true
		tccutil reset All sh.makima.desktop >/dev/null 2>&1 || true
	fi

	# Root's copy of the binaries, which the app runs through sudo so that
	# its buttons stop asking for a password — refreshed from the new
	# bundle, with its times, which is how the app knows its copy is current.
	if [ -d "$TRUSTED" ]; then
		for b in $BINS; do
			sudo install -p -m 0755 "/Applications/makima.app/Contents/MacOS/$b" "$TRUSTED/$b" || return 1
		done
	fi
}

# On Debian and Ubuntu the app is a package, put in through apt so that what
# it depends on — tor and pkexec among it — comes with it. The system's own
# tor service, which makima never uses, is not left running when installing
# the app is what started it.
place_deb_app() {
	tor_was_here=
	command -v tor >/dev/null 2>&1 && tor_was_here=1
	say "installing the app (apt)"
	# apt reads the package as its own user, and mktemp's directory is ours.
	chmod 755 "$tmp"
	as_root apt-get -o DPkg::Lock::Timeout=300 install -y -q --reinstall "$tmp/$app" >/dev/null || return 1
	if [ -z "$tor_was_here" ]; then
		as_root systemctl disable --now tor >/dev/null 2>&1 || true
	fi
}

# Everything that replaces something, as one step, so that whatever happens
# in it the machine is started again afterwards rather than left with its
# tunnel down.
place() {
	$sudo mkdir -p "$BINDIR" || return 1
	for b in $BINS; do
		$sudo install -m 0755 "$tmp/$name/$b" "$BINDIR/$b" || return 1
	done
	case "$app" in
	"") ;;
	*.deb) place_deb_app ;;
	*) place_mac_app ;;
	esac
}

if [ -n "$updater" ]; then sh "$updater" stop || true; fi
placed=1
place || placed=
if [ -n "$updater" ]; then sh "$updater" start || true; fi
[ -n "$placed" ] || die "the install did not finish; what was running has been started again"

# --- what now -------------------------------------------------------------

installed="makima, makimad, makima-server, makima-relay"
[ -z "$app" ] || installed="$installed, and the app"

cat <<EOF

Installed: $installed

Try it without changing anything on this machine:
  makima try -serve 8080

Or set up a real mesh, which needs root:
  makima up

EOF

# The app, open, so that the install ends with it on the screen.
if [ -n "$app" ]; then
	if [ "$os" = darwin ]; then
		open /Applications/makima.app >/dev/null 2>&1 || true
	elif [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && ! pgrep -x makima-desktop >/dev/null 2>&1; then
		(setsid makima-desktop >/dev/null 2>&1 &)
	else
		say "the app is in your applications as makima"
	fi
fi

# tor is how the network is reached from anywhere. Installing system
# packages is not this script's business beyond the app's own, so it only
# says so.
if ! command -v tor >/dev/null 2>&1 && [ ! -x /opt/homebrew/bin/tor ] && [ ! -x /usr/bin/tor ] && [ ! -x /usr/sbin/tor ]; then
	cat <<EOF
To reach the network from anywhere, not just from where its server is,
install tor too:
  brew install tor          # macOS
  sudo apt install tor      # Debian, Ubuntu

EOF
fi
