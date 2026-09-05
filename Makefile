# makima — build, install, and restart the node daemon, and the app with it.
#
# `make` alone does the whole golden path. Nothing else needs to be run by hand.
# Where a Rust toolchain and bun are present, that includes the desktop app:
# built, put in /Applications (or installed as a package on Linux), and
# relaunched — so the app on the machine is never older than the code.

BINDIR  := /usr/local/bin
BINS    := makima makimad makima-server makima-relay
BUILD   := build
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Platforms a release is built for. One line, so adding a platform is a
# one-word change and every part of the release machinery follows.
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 linux/arm windows/amd64

RELEASE := dist/release

# The desktop app needs Rust and bun, which the four binaries do not. It joins
# the golden path when both are here, and is skipped with a note when not, so
# that somebody building a VPN from source is never told to install a UI
# toolchain first.
TRIPLE   := $(shell rustc -vV 2>/dev/null | sed -n 's/^host: //p')
HAVE_APP := $(and $(TRIPLE),$(shell command -v bun 2>/dev/null))

.PHONY: all build install update restart stop clean test race fmt vet check cross service release release-clean sidecars app app-build app-install app-skip app-dev

all: build install $(if $(HAVE_APP),app,app-skip) restart

build:
	@mkdir -p $(BUILD)
	@for b in $(BINS); do \
		echo "  build  $$b"; \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD)/$$b ./cmd/$$b || exit 1; \
	done

install: build
	@for b in $(BINS); do \
		echo "  install $(BINDIR)/$$b"; \
		sudo install -m 0755 $(BUILD)/$$b $(BINDIR)/$$b || exit 1; \
	done

# The daemon holds a TUN device open, so a new binary means nothing until the
# old process lets go of the interface. stop/restart exist so that is never a
# manual step.
#
# `makima down` rather than pkill: the daemon is registered with launchd or
# systemd, which would start it straight back up if it were merely killed.
# The old binary is used to stop, since it is the one that registered it.
stop:
	@if [ -x $(BINDIR)/makima ] && [ -f /etc/makima/node.json ]; then \
		sudo $(BINDIR)/makima down >/dev/null 2>&1 && echo "  stopped makima" || sudo pkill -x makimad 2>/dev/null || true; \
	else \
		sudo pkill -x makimad 2>/dev/null && echo "  stopped makimad" || true; \
	fi

# Back up with the new binary, if this machine is on a network at all. A
# machine that is not is left alone: `makima up` on it would start a network,
# and that is a thing to be asked for.
restart:
	@if [ -f /etc/makima/node.json ]; then \
		echo "  bringing makima back up"; sudo $(BINDIR)/makima up; \
	else \
		echo "  makima installed. start with: makima up"; \
	fi

update: stop
	@for b in $(BINS); do sudo rm -f $(BINDIR)/$$b; done
	@$(MAKE) --no-print-directory install
	@if [ -n "$(HAVE_APP)" ] && [ -d /Applications/makima.app -o -x /usr/bin/makima-desktop ]; then \
		$(MAKE) --no-print-directory app; \
	fi
	@$(MAKE) --no-print-directory restart

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
	@for t in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do \
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
		cp -R dist/install-service.sh dist/*.service dist/*.plist $$dir/ 2>/dev/null || true; \
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

sidecars:
	@test -n "$(TRIPLE)" || { echo "rustc not found; the app needs a Rust toolchain"; exit 1; }
	@mkdir -p $(SIDECARS)
	@for b in $(BINS); do \
		echo "  sidecar $$b-$(TRIPLE)"; \
		CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(SIDECARS)/$$b-$(TRIPLE) ./cmd/$$b || exit 1; \
	done

# Build it and put it where apps go, then open it — so `make` ends with the
# new app in the menu bar, not with a bundle in a target directory.
app: app-build app-install

app-build: sidecars
	@cd desktop && bun install --frozen-lockfile && bun run tauri build

app-install:
	@if [ "$$(uname -s)" = Darwin ]; then \
		echo "  install $(APP)"; \
		osascript -e 'quit app "makima"' >/dev/null 2>&1 || true; \
		rm -rf $(APP); \
		cp -R $(BUNDLE)/macos/makima.app $(APP); \
		open $(APP); \
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

app-skip:
	@echo "  app     skipped: needs rustc and bun (see desktop/README.md)"

# The app against a pretend mesh, so the interface can be worked on without
# root and without a tunnel. Two processes; this runs the second.
app-dev: sidecars
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
