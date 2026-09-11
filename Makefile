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

.PHONY: all build install update update-stop update-delete update-start trusted-copy restart clean test race fmt vet check cross service release release-clean sidecars app app-build app-install app-place app-skip app-dev dmg

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

# Back up with the new binary, if this machine is on a network at all. A
# machine that is not is left alone: `makima up` on it would start a network,
# and that is a thing to be asked for.
restart:
	@if [ -f /etc/makima/node.json ]; then \
		echo "  bringing makima back up"; sudo $(BINDIR)/makima up; \
	else \
		echo "  makima installed. start with: makima up"; \
	fi

# update: stop everything running the old binaries, delete them, build and
# install the new ones, then start again exactly what was stopped.
#
# "Exactly what was stopped" is the point. Up to three daemons can be running —
# the node, and on the machine holding the mesh its server and relay — and
# `makima down`/`up` only know about the node, so an update that went through
# them left the server running the old code indefinitely. A node that was down
# on purpose stays down, too. What was running is written to $(UPSTATE) on the
# way down and read back on the way up.
LABELS  := sh.makima.makimad sh.makima.server sh.makima.relay
UNITS   := makimad makima-server makima-relay
UPSTATE := $(BUILD)/.update
# Root's copy of the binaries, which the app runs through sudo so its buttons
# stop asking for a password (desktop/src-tauri/src/privileged.rs). Replaced
# alongside the app; left stale, the app's first click would ask again.
TRUSTED := /Library/PrivilegedHelperTools/makima

update:
	@app=""; if [ -n "$(HAVE_APP)" ] && [ -d $(APP) -o -x /usr/bin/makima-desktop ]; then app=1; fi; \
	$(MAKE) --no-print-directory update-stop && \
	$(MAKE) --no-print-directory update-delete UPDATE_APP=$$app && \
	$(MAKE) --no-print-directory install && \
	if [ -n "$$app" ]; then $(MAKE) --no-print-directory app-build app-place trusted-copy; fi && \
	$(MAKE) --no-print-directory update-start

# launchd and systemd first: a service killed out from under its manager is
# started straight back up on the old binary. bootout is also what `makima
# down` does, so the node gets its SIGTERM and puts the routes back — but the
# definition stays on disk to be bootstrapped again. Anything left after that
# was started by hand and is stopped directly, with its command line kept so it
# can be started the same way.
update-stop:
	@mkdir -p $(UPSTATE) && rm -f $(UPSTATE)/*
	@if [ "$$(uname -s)" = Darwin ]; then \
		for l in $(LABELS); do \
			if sudo launchctl print system/$$l >/dev/null 2>&1; then \
				echo "  stop    $$l"; echo $$l >> $(UPSTATE)/launchd; \
				sudo launchctl bootout system/$$l 2>/dev/null || true; \
			fi; \
		done; \
	elif command -v systemctl >/dev/null 2>&1; then \
		for u in $(UNITS); do \
			if systemctl is-active --quiet $$u; then \
				echo "  stop    $$u"; echo $$u >> $(UPSTATE)/systemd; sudo systemctl stop $$u; \
			fi; \
		done; \
	fi
	@for b in $(UNITS); do \
		for pid in $$(pgrep -x $$b); do \
			echo "  stop    $$b (pid $$pid)"; \
			echo "$$b $$(ps -o args= -p $$pid)" >> $(UPSTATE)/spawned; \
			sudo kill -TERM $$pid 2>/dev/null || true; \
		done; \
	done
	@i=0; while pgrep -x 'makimad|makima-server|makima-relay' >/dev/null 2>&1 && [ $$i -lt 80 ]; do sleep 0.25; i=$$((i+1)); done; \
	if pgrep -x 'makimad|makima-server|makima-relay' >/dev/null 2>&1; then echo "  a makima daemon did not exit within 20s"; exit 1; fi
	@if pgrep -x makima-desktop >/dev/null 2>&1; then \
		echo "  stop    makima app"; touch $(UPSTATE)/app; \
		osascript -e 'quit app "makima"' >/dev/null 2>&1 || true; \
		pkill -x makima-desktop 2>/dev/null || true; \
		i=0; while pgrep -x makima-desktop >/dev/null 2>&1 && [ $$i -lt 40 ]; do sleep 0.25; i=$$((i+1)); done; \
	fi

# The binaries, and — when the app is being rebuilt — the app and root's copy.
# On Linux the app is a package, and installing the new one replaces it.
update-delete:
	@for b in $(BINS); do sudo rm -f $(BINDIR)/$$b; done; echo "  delete  $(BINDIR)/{$$(echo $(BINS) | tr ' ' ,)}"
	@if [ -n "$(UPDATE_APP)" ] && [ "$$(uname -s)" = Darwin ]; then \
		echo "  delete  $(APP)"; rm -rf $(APP); \
		if [ -d $(TRUSTED) ]; then echo "  delete  $(TRUSTED)/*"; sudo rm -f $(TRUSTED)/*; fi; \
	fi

# Put back what update-stop wrote down. A definition that will not bootstrap —
# one naming a binary that no longer exists — is re-registered by `makima up`
# for the node, and reported for anything else.
update-start:
	@if [ -f $(UPSTATE)/launchd ]; then \
		for l in $$(cat $(UPSTATE)/launchd); do \
			echo "  start   $$l"; \
			sudo launchctl bootstrap system /Library/LaunchDaemons/$$l.plist 2>/dev/null || \
				[ $$l = sh.makima.makimad ] || echo "  could not start $$l — see /var/log/makima/"; \
		done; \
	fi
	@if [ -f $(UPSTATE)/systemd ]; then \
		for u in $$(cat $(UPSTATE)/systemd); do echo "  start   $$u"; sudo systemctl start $$u; done; \
	fi
	@if [ -f $(UPSTATE)/spawned ]; then \
		while read -r name args; do \
			[ $$name = makimad ] && continue; \
			bin=$(BINDIR)/$$name; set -- $$args; shift; \
			echo "  start   $$name"; \
			sudo mkdir -p /var/log/makima; \
			sudo sh -c "nohup $$bin $$* >>/var/log/makima/$$name.log 2>&1 &"; \
		done < $(UPSTATE)/spawned; \
	fi
	@if grep -qs -e sh.makima.makimad -e '^makimad' $(UPSTATE)/launchd $(UPSTATE)/systemd $(UPSTATE)/spawned && \
		! pgrep -x makimad >/dev/null 2>&1; then \
		sleep 1; pgrep -x makimad >/dev/null 2>&1 || { echo "  start   makimad"; sudo $(BINDIR)/makima up; }; \
	fi
	@if [ -f $(UPSTATE)/app ]; then \
		echo "  start   makima app"; \
		if [ "$$(uname -s)" = Darwin ]; then open $(APP); else (setsid makima-desktop >/dev/null 2>&1 &); fi; \
	fi
	@rm -rf $(UPSTATE)

# Refresh root's copy of the binaries from the app just installed, if the app
# has made one. `install -p` keeps the modification times, which is how the app
# tells its copy is current.
trusted-copy:
	@if [ "$$(uname -s)" = Darwin ] && [ -d $(TRUSTED) ] && [ -d $(APP) ]; then \
		echo "  install $(TRUSTED)"; \
		for b in $(BINS); do \
			[ -f $(APP)/Contents/MacOS/$$b ] && sudo install -p -o root -g wheel -m 0755 $(APP)/Contents/MacOS/$$b $(TRUSTED)/$$b; \
		done; true; \
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

# On a Mac only the .app is built here: the .dmg is for handing the app to
# somebody else, and its packaging step leaves a mounted volume behind when it
# is interrupted, after which every later build fails at that step. `make
# dmg` produces one on purpose.
app-build: sidecars
	@cd desktop && bun install --frozen-lockfile && \
		if [ "$$(uname -s)" = Darwin ]; then bun run tauri build --bundles app; else bun run tauri build; fi

dmg: sidecars
	@cd desktop && bun install --frozen-lockfile && bun run tauri build --bundles dmg

app-install: app-place trusted-copy
	@if [ "$$(uname -s)" = Darwin ]; then open $(APP); fi

# The app where apps go, without opening it: `update` decides that itself,
# from whether it was running before.
app-place:
	@if [ "$$(uname -s)" = Darwin ]; then \
		echo "  install $(APP)"; \
		osascript -e 'quit app "makima"' >/dev/null 2>&1 || true; \
		pkill -x makima-desktop 2>/dev/null || true; \
		i=0; while pgrep -x makima-desktop >/dev/null 2>&1 && [ $$i -lt 40 ]; do sleep 0.25; i=$$((i+1)); done; \
		rm -rf $(APP); \
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
