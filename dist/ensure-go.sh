#!/bin/sh
# ensure-go.sh — make sure there is a Go here new enough to build makima.
#
#   sh dist/ensure-go.sh 1.26.0     the oldest Go that will do: go.mod's
#
# A Go that new or newer, on PATH or in /usr/local/go, is left alone. Otherwise
# the current release is fetched from go.dev and put where go.dev says to put
# it, /usr/local/go, with go and gofmt linked into /usr/local/bin so that the
# next shell finds them without anybody editing a profile.
#
# A Go that is too old is replaced rather than left to fetch a newer one for
# itself: Debian and Ubuntu build theirs with GOTOOLCHAIN=local, which never
# does, and a Jetson's Ubuntu ships one years behind go.mod.
set -eu

need=${1:?usage: sh dist/ensure-go.sh <oldest go version>}

# The same order make uses (Makefile, PATH), so the Go checked here is the Go
# that builds.
PATH=/usr/local/go/bin:$PATH

SUDO=sudo
[ "$(id -u)" = 0 ] && SUDO=

# Whether the go on PATH is at least $need. GOTOOLCHAIN=local, so that asking
# a Go of 1.21 or later its version does not have it go and fetch go.mod's.
new_enough() {
	have=$(GOTOOLCHAIN=local go version 2>/dev/null | sed -n 's/^go version go\([0-9.]*\).*/\1/p')
	[ -n "$have" ] || return 1
	printf '%s %s\n' "$have" "$need" | awk '{
		split($1, a, "."); split($2, b, ".")
		for (i = 1; i <= 3; i++) if (a[i] + 0 != b[i] + 0) exit !(a[i] + 0 > b[i] + 0)
		exit 0
	}'
}

new_enough && exit 0

case $(uname -s) in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) echo "  install Go $need or newer: https://go.dev/dl/"; exit 1 ;;
esac
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
armv6l | armv7l) arch=armv6l ;;
*) echo "  no Go from go.dev for $(uname -m) — install Go $need or newer"; exit 1 ;;
esac

fetch() {
	if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"; else wget -qO- "$1"; fi
}

version=$(fetch 'https://go.dev/VERSION?m=text' | head -n 1)
case $version in
go1.*) ;;
*) echo "  could not ask go.dev for the current Go (needs curl or wget, and the internet)"; exit 1 ;;
esac

if command -v go >/dev/null 2>&1; then
	echo "  install Go ${version#go} (go.dev), over $(GOTOOLCHAIN=local go version | cut -d' ' -f3)"
else
	echo "  install Go ${version#go} (go.dev)"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fetch "https://go.dev/dl/$version.$os-$arch.tar.gz" >"$tmp/go.tar.gz"

# Read through once before the old Go is removed, so that a download cut short
# fails here and leaves the machine with the Go it had.
tar -tzf "$tmp/go.tar.gz" >/dev/null
$SUDO rm -rf /usr/local/go
$SUDO tar -C /usr/local -xzf "$tmp/go.tar.gz"

# Linked only where nothing else is: a go in /usr/local/bin that somebody put
# there themselves is theirs.
$SUDO mkdir -p /usr/local/bin
for t in go gofmt; do
	if [ ! -e /usr/local/bin/$t ] || [ -L /usr/local/bin/$t ]; then
		$SUDO ln -sf /usr/local/go/bin/$t /usr/local/bin/$t
	fi
done

hash -r 2>/dev/null || true
new_enough || { echo "  Go ${version#go} is in /usr/local/go, but it is not new enough to build makima"; exit 1; }
