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
# It downloads one archive, verifies it against the release's published
# SHA256SUMS, and copies four binaries into place. It starts nothing, enables
# nothing at boot, and touches no network configuration — `makima up` does all
# of that, when it is asked to.
set -eu

REPO=${MAKIMA_REPO:-justin06lee/makima}
VERSION=${MAKIMA_VERSION:-latest}
BINDIR=${MAKIMA_BINDIR:-/usr/local/bin}

die() { echo "install: $*" >&2; exit 1; }
say() { echo "  $*"; }

need() { command -v "$1" >/dev/null 2>&1 || die "this needs $1"; }

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

# --- download and verify --------------------------------------------------

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading"
curl -fsSL "$base/$name.tar.gz" -o "$tmp/$name.tar.gz" ||
	die "no build published for $os/$arch at $VERSION"

# Checked, not assumed. A binary that is about to be run as root and handed a
# network interface is exactly the wrong thing to take on trust from a CDN.
if curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" 2>/dev/null; then
	if command -v sha256sum >/dev/null 2>&1; then
		want=$(grep " $name.tar.gz\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
		got=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
	elif command -v shasum >/dev/null 2>&1; then
		want=$(grep " $name.tar.gz\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
		got=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
	else
		want=""; got=""
		say "no sha256 tool here; skipping the checksum"
	fi

	if [ -n "$want" ]; then
		[ "$want" = "$got" ] || die "checksum mismatch — refusing to install
  expected $want
  got      $got"
		say "checksum ok"
	fi
else
	say "no published checksums for $VERSION; skipping verification"
fi

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"

# --- install --------------------------------------------------------------

sudo=""
if [ ! -w "$BINDIR" ]; then
	command -v sudo >/dev/null 2>&1 || die "$BINDIR is not writable and there is no sudo"
	sudo=sudo
	say "installing to $BINDIR (needs sudo)"
else
	say "installing to $BINDIR"
fi

$sudo mkdir -p "$BINDIR"
for b in makima makimad makima-server makima-relay; do
	$sudo install -m 0755 "$tmp/$name/$b" "$BINDIR/$b"
done

# --- what now -------------------------------------------------------------

cat <<EOF

Installed: makima, makimad, makima-server, makima-relay

Try it without changing anything on this machine:
  makima try -serve 8080

Or set up a real mesh, which needs root:
  makima up

EOF
