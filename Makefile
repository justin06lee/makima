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
#
# It is handed to Tauri at build time rather than written into those files.
# Writing it made every build after a release modify two tracked files, so the
# next build — and every binary it stamped — called itself v0.3.0-dirty. The
# number in the files is only what a bare `bun run tauri dev` falls back to.
APP_VERSION := $(shell git describe --tags --match 'v*' --abbrev=0 2>/dev/null | sed 's/^v//' || echo 0.0.0)
APP_CONFIG  := --config '{"version":"$(APP_VERSION)"}'
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

.PHONY: all build install install-bins update stop start uninstall reset-permissions trusted-copy app-version clean test race fmt vet check cross service release release-clean sidecars kits app app-build app-install app-place app-open app-skip app-dev dmg

# `make` is the whole golden path: build everything, put it in place, and start
# again exactly what was running.
#
# It keeps the machine's state. An install used to run dist/uninstall.sh first,
# so every one of them was a new machine — the network this box was on or
# *held* forgotten, its keys gone, its invites spent. A reinstall is not a
# reason to lose a network, and a build command that can is one people are
# right to be afraid of.
#
# `make uninstall` is still there for when removing makima is the point.
all: install

# Everything is built before anything is taken down, so a build that fails
# leaves the machine exactly as it was rather than with nothing on it.
install: build $(if $(HAVE_APP),app-build) stop install-bins $(if $(HAVE_APP),app-place reset-permissions trusted-copy,app-skip) start $(if $(HAVE_APP),app-open)

# update is the same path: stop, replace, start. Kept as its own name because
# it is the one people type when they mean "pick up my changes".
update: install

build:
	@mkdir -p $(BUILD)
	@for b in $(BINS); do \
		echo "  build  $$b"; \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD)/$$b ./cmd/$$b || exit 1; \
	done

# The binaries themselves. Root's copy too, where the app has made one: the
# daemon may be registered to run from there rather than from $(BINDIR), and
# replacing only one of the two leaves the old code running.
install-bins:
	@for b in $(BINS); do \
		echo "  install $(BINDIR)/$$b"; \
		sudo install -m 0755 $(BUILD)/$$b $(BINDIR)/$$b || exit 1; \
	done
	@$(if $(HAVE_APP),true,echo "  makima installed. start with: makima up")

# Root's copy of the binaries, which the app runs through sudo so its buttons
# stop asking for a password (desktop/src-tauri/src/privileged.rs).
TRUSTED := /Library/PrivilegedHelperTools/makima

# Refresh that copy from the app just installed, where there is one.
#
# Two reasons it is the bundle's copies rather than $(BUILD)'s. The daemon may
# be registered to run from in there — launchd records the path it was given —
# so leaving it stale would keep the old code running after an install. And
# `install -p` carries the modification times over, which is exactly how the
# app decides its copy is current: from a different source they would differ,
# and the first click after every install would ask for a password again.
trusted-copy:
	@if [ "$$(uname -s)" = Darwin ] && [ -d $(TRUSTED) ] && [ -d $(APP) ]; then \
		for b in $(BINS); do \
			sudo install -p -m 0755 $(APP)/Contents/MacOS/$$b $(TRUSTED)/$$b || exit 1; \
		done; \
		echo "  install $(TRUSTED)/*"; \
	fi

# Stop what is running, and start back exactly that. Neither touches state:
# dist/update.sh says what it does and does not do.
stop:
	@sudo sh dist/update.sh stop

start:
	@sudo sh dist/update.sh start

# Taking makima off the machine, which is a thing to ask for rather than a step
# on the way to installing it.
uninstall:
	@sudo sh dist/uninstall.sh

# macOS ties a privacy grant to the binary that was granted it, so a rebuilt
# app inherits a stale entry that looks enabled in System Settings and is not.
# Resetting is the app's own bundle id and nothing else.
reset-permissions:
	@if [ "$$(uname -s)" = Darwin ]; then \
		osascript -e 'quit app "System Settings"' >/dev/null 2>&1 || true; \
		tccutil reset All sh.makima.desktop >/dev/null 2>&1 || true; \
	fi

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

# The versions a build is about to stamp. Nothing is written: see APP_CONFIG.
app-version:
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

# Build it and put it where apps go, then open it — so `make app` ends with the
# new app in the menu bar, not with a bundle in a target directory.
app: app-build stop app-place reset-permissions trusted-copy start app-open

# On a Mac only the .app is built here: the .dmg is for handing the app to
# somebody else, and its packaging step leaves a mounted volume behind when it
# is interrupted, after which every later build fails at that step. `make
# dmg` produces one on purpose.
app-build: app-version sidecars
	@cd desktop && bun install --frozen-lockfile && \
		if [ "$$(uname -s)" = Darwin ]; then bun run tauri build $(APP_CONFIG) --bundles app; else bun run tauri build $(APP_CONFIG); fi

dmg: app-version sidecars
	@cd desktop && bun install --frozen-lockfile && bun run tauri build $(APP_CONFIG) --bundles dmg

app-install: stop app-place reset-permissions trusted-copy start app-open

# The app where apps go, over whatever was there. `stop` has already quit it.
app-place:
	@if [ "$$(uname -s)" = Darwin ] && [ -d $(APP) ]; then rm -rf $(APP); fi
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
	@cd desktop && MAKIMA_GUI_SOCKET=/tmp/makima-dev.sock bun run tauri dev $(APP_CONFIG)

release-clean:
	@rm -rf $(RELEASE)

clean: release-clean
	@rm -rf $(BUILD)
# Service units, by hand. `makima up` registers the daemon with launchd or
# systemd itself; this installs the hardened units in dist/ instead, for a
# server somebody administers themselves.
service:
	@sudo sh dist/install-service.sh
