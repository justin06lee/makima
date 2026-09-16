# makima — build, install, and restart the node daemon, and the app with it.
#
# `make` alone does the whole golden path. Nothing else needs to be run by hand.
# Where a Rust toolchain and bun are present, that includes the desktop app:
# built, put in /Applications (or installed as a package on Linux), and
# relaunched — so the app on the machine is never older than the code.

BINDIR  := /usr/local/bin
BINS    := makima makimad makima-server makima-relay
BUILD   := build
# --match 'v*' on purpose: a tag that is not a version is not a version. Without
# it, `git describe` picks up whatever annotated tag is nearest — including the
# per-branch ones this repository used to carry — and stamps a branch name into
# every binary as its version number.
VERSION := $(shell git describe --tags --match 'v*' --always --dirty 2>/dev/null || echo dev)

# The app bundle's version. Tauri and macOS both want plain semver, so this is
# the last release rather than the full describe — the running version the app
# actually shows comes from the daemon, which carries VERSION above.
#
# It exists so that the number is in one place. Two files used to hold it by
# hand, and a hand-held version number is one that is right until the first
# release nobody remembered to edit it for.
APP_VERSION := $(shell git describe --tags --match 'v*' --abbrev=0 2>/dev/null | sed 's/^v//' || echo 0.0.0)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Platforms a release is built for. One line, so adding a platform is a
# one-word change and every part of the release machinery follows — `cross`
# included, which is what proves the one-binary-per-platform promise still
# holds.
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 linux/arm windows/amd64

RELEASE := dist/release

# The desktop app needs Rust and bun, which the four binaries do not. It joins
# the golden path when both are here, and is skipped with a note when not, so
# that somebody building a VPN from source is never told to install a UI
# toolchain first.
TRIPLE   := $(shell rustc -vV 2>/dev/null | sed -n 's/^host: //p')
HAVE_APP := $(and $(TRIPLE),$(shell command -v bun 2>/dev/null))

.PHONY: all build install install-bins reinstall update app-version clean-slate clean test race fmt vet check cross service release release-clean sidecars kits app app-build app-install app-place app-open app-skip app-dev dmg

# `make` builds. It does not touch the machine.
#
# It used to run the golden path — build, wipe every trace of makima off this
# machine, install, relaunch — because that is what somebody working on makima
# wants most of the time. It is not what somebody who typed `make` to see
# whether the tree compiles wants, and the two are indistinguishable until it
# has already happened: clean-slate stops the daemon, forgets the network this
# machine is on *or holds*, and takes its launchd and systemd registrations
# with it. A build command that can lose a network is a build command people
# are right to be afraid of.
#
# `make install` is now the golden path, and it says what it does.
all: build
	@echo "  built into $(BUILD)/. 'make install' replaces makima on this machine."

# Everything is built before anything is taken down, so a build that fails
# leaves the machine exactly as it was rather than with nothing on it.
reinstall: build $(if $(HAVE_APP),app-build) install-bins $(if $(HAVE_APP),app-place app-open,app-skip)

# update is the golden path: every install is already a full stop, delete and
# replace, so there is nothing left for a separate update to do differently.
update: reinstall

build:
	@mkdir -p $(BUILD)
	@for b in $(BINS); do \
		echo "  build  $$b"; \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD)/$$b ./cmd/$$b || exit 1; \
	done

install: reinstall

# install-bins is the copy step on its own, so `reinstall` can order the wipe
# and the copy itself rather than through a prerequisite.
install-bins: clean-slate
	@for b in $(BINS); do \
		echo "  install $(BINDIR)/$$b"; \
		sudo install -m 0755 $(BUILD)/$$b $(BINDIR)/$$b || exit 1; \
	done
	@$(if $(HAVE_APP),true,echo "  makima installed. start with: makima up")

# Every install starts from a machine that has never seen makima: the app and
# daemons stopped, their registrations gone, the network this machine was on or
# held forgotten, and every file any earlier version left behind deleted —
# dist/uninstall.sh says what that is. A new build meeting an old network's
# state is how "this machine is already on the network held at …" happens.
#
# Nothing is restarted afterwards, because there is nothing left to restart:
# the app opens on its first screen, where a network is started or joined.
clean-slate:
	@sudo sh dist/uninstall.sh

check: fmt vet test race

race:
	@go test -race ./... >/dev/null && echo "  race ok"

fmt:
	@gofmt -l . | grep -v '^$$' && { echo "unformatted files above"; exit 1; } || echo "  fmt ok"

vet:
	@go vet ./... && echo "  vet ok"

test:
	@go test ./... 

# Proof that the one-binary-per-platform promise actually holds.
cross:
	@for t in $(PLATFORMS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		printf "  %-16s" "$$t"; \
		GOOS=$$os GOARCH=$$arch go build -o /dev/null ./... && echo ok || exit 1; \
	done

# Release archives, one per platform, plus the checksums that make them
# verifiable.
#
# The reason this exists at all: `make` from source is the single biggest
# barrier to anybody actually using this, and no amount of CLI polish fixes it.
# Somebody who has to install Go before they can find out whether a VPN works
# will not find out whether a VPN works.
#
# -trimpath and a fixed -buildid make the output reproducible: two people
# building the same tag get byte-identical archives, so a published checksum is
# something anybody can check rather than something they have to trust.
release: release-clean
	@mkdir -p $(RELEASE)
	@for t in $(PLATFORMS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		dir=$(RELEASE)/makima-$(VERSION)-$$os-$$arch; \
		mkdir -p $$dir; \
		ext=""; [ "$$os" = windows ] && ext=".exe"; \
		printf "  %-22s" "$$os/$$arch"; \
		for b in $(BINS); do \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
				go build -trimpath -ldflags "$(LDFLAGS) -buildid=" \
				-o $$dir/$$b$$ext ./cmd/$$b || exit 1; \
		done; \
		cp README.md LICENSE $$dir/; \
		cp -R dist/install-service.sh dist/uninstall.sh dist/*.service dist/*.plist $$dir/ 2>/dev/null || true; \
		if [ "$$os" = windows ]; then \
			(cd $(RELEASE) && zip -qr $$(basename $$dir).zip $$(basename $$dir)); \
		else \
			tar -C $(RELEASE) -czf $$dir.tar.gz $$(basename $$dir); \
		fi; \
		rm -rf $$dir; \
		echo ok; \
	done
	@cd $(RELEASE) && (sha256sum *.tar.gz *.zip 2>/dev/null || shasum -a 256 *.tar.gz *.zip) > SHA256SUMS && \
		echo "  checksums              $(RELEASE)/SHA256SUMS"

# The desktop app.
#
# It needs Rust, bun and — on Linux — GTK and webkit2gtk, none of which the
# four binaries require, so it is part of `make` only where those are found.
#
# The app carries the four binaries inside its bundle, so that downloading it
# is the whole install: Tauri calls these "sidecars" and wants them named for
# the target triple. `sidecars` builds them for this machine; the app target
# bundles whatever is there.
SIDECARS := desktop/src-tauri/binaries
BUNDLE   := desktop/src-tauri/target/release/bundle
APP      := /Applications/makima.app

# The bundle's version, written from the last release tag into the two files
# that carry it.
app-version:
	@for f in desktop/package.json desktop/src-tauri/tauri.conf.json; do \
		sed -i.bak 's/^\(  "version": \)"[^"]*"/\1"$(APP_VERSION)"/' $$f && rm -f $$f.bak; \
	done
	@echo "  version $(APP_VERSION) (app bundle), $(VERSION) (binaries)"

sidecars: kits
	@test -n "$(TRIPLE)" || { echo "rustc not found; the app needs a Rust toolchain"; exit 1; }
	@mkdir -p $(SIDECARS)
	@for b in $(BINS); do \
		echo "  sidecar $$b-$(TRIPLE)"; \
		CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(SIDECARS)/$$b-$(TRIPLE) ./cmd/$$b || exit 1; \
	done

# Kits: the four binaries for every platform but this one, carried inside the
# app as resources. Moving from Tailscale installs makima on the other
# machines from the Mac (or Linux box) it runs on, and a Linux server needs
# Linux binaries — which, this way, never have to come from the internet, and
# are always exactly the version of the app doing the installing.
# internal/migrate/kit.go reads them as makima-<os>-<arch>.tar.gz.
KITS          := desktop/src-tauri/kits
KIT_PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 linux/arm
HOST_PLATFORM := $(shell go env GOOS)/$(shell go env GOARCH)

kits:
	@mkdir -p $(KITS)
	@for t in $(filter-out $(HOST_PLATFORM),$(KIT_PLATFORMS)); do \
		os=$${t%/*}; arch=$${t#*/}; \
		dir=$$(mktemp -d)/makima; mkdir -p $$dir; \
		printf "  kit     %s\n" "$$t"; \
		for b in $(BINS); do \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $$dir/$$b ./cmd/$$b || exit 1; \
		done; \
		tar -C $$(dirname $$dir) -czf $(KITS)/makima-$$os-$$arch.tar.gz makima || exit 1; \
		rm -rf $$(dirname $$dir); \
	done

# Build it and put it where apps go, then open it — so `make` ends with the
# new app in the menu bar, not with a bundle in a target directory. Like every
# install, it replaces all of makima on this machine, not just the app.
app: app-build clean-slate app-place app-open

# On a Mac only the .app is built here: the .dmg is for handing the app to
# somebody else, and its packaging step leaves a mounted volume behind when it
# is interrupted, after which every later build fails at that step. `make
# dmg` produces one on purpose.
app-build: app-version sidecars
	@cd desktop && bun install --frozen-lockfile && \
		if [ "$$(uname -s)" = Darwin ]; then bun run tauri build --bundles app; else bun run tauri build; fi

dmg: app-version sidecars
	@cd desktop && bun install --frozen-lockfile && bun run tauri build --bundles dmg

app-install: clean-slate app-place app-open

# The app where apps go. clean-slate has already stopped and removed the old one.
app-place:
	@if [ "$$(uname -s)" = Darwin ]; then \
		echo "  install $(APP)"; \
		cp -R $(BUNDLE)/macos/makima.app $(APP); \
	elif command -v dpkg >/dev/null 2>&1 && ls $(BUNDLE)/deb/*.deb >/dev/null 2>&1; then \
		echo "  install $$(ls $(BUNDLE)/deb/*.deb | tail -1)"; \
		sudo dpkg -i $$(ls $(BUNDLE)/deb/*.deb | tail -1); \
	elif command -v rpm >/dev/null 2>&1 && ls $(BUNDLE)/rpm/*.rpm >/dev/null 2>&1; then \
		echo "  install $$(ls $(BUNDLE)/rpm/*.rpm | tail -1)"; \
		sudo rpm -U --replacepkgs $$(ls $(BUNDLE)/rpm/*.rpm | tail -1); \
	elif ls $(BUNDLE)/appimage/*.AppImage >/dev/null 2>&1; then \
		echo "  install /usr/local/bin/makima-desktop"; \
		sudo install -m 0755 $$(ls $(BUNDLE)/appimage/*.AppImage | tail -1) /usr/local/bin/makima-desktop; \
	else \
		echo "  the app is built under $(BUNDLE); nothing here knows how to install it"; \
	fi

app-open:
	@if [ "$$(uname -s)" = Darwin ]; then \
		echo "  open    $(APP)"; open $(APP); \
	elif [ -n "$${DISPLAY:-}$${WAYLAND_DISPLAY:-}" ] && command -v makima-desktop >/dev/null 2>&1; then \
		echo "  open    makima-desktop"; (setsid makima-desktop >/dev/null 2>&1 &); \
	fi

app-skip:
	@echo "  app     skipped: needs rustc and bun (see desktop/README.md)"

# The app against a pretend mesh, so the interface can be worked on without
# root and without a tunnel. Two processes; this runs the second.
app-dev: app-version sidecars
	@echo "  run 'go run ./desktop/devserver' in another terminal first"
	@cd desktop && MAKIMA_GUI_SOCKET=/tmp/makima-dev.sock bun run tauri dev

release-clean:
	@rm -rf $(RELEASE)

clean: release-clean
	@rm -rf $(BUILD)
# Service units, by hand. `makima up` registers the daemon with launchd or
# systemd itself; this installs the hardened units in dist/ instead, for a
# server somebody administers themselves.
service:
	@sh dist/install-service.sh
