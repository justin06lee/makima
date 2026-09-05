# makima — build, install, and restart the node daemon.
#
# `make` alone does the whole golden path. Nothing else needs to be run by hand.

BINDIR  := /usr/local/bin
BINS    := makima makimad makima-server makima-relay
BUILD   := build
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Platforms a release is built for. One line, so adding a platform is a
# one-word change and every part of the release machinery follows.
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 linux/arm windows/amd64

RELEASE := dist/release

.PHONY: all build install update restart stop clean test race fmt vet check cross service release release-clean app app-dev

all: build install restart

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
stop:
	@sudo pkill -x makimad 2>/dev/null && echo "  stopped makimad" || true

restart: stop
	@echo "  makima installed. bring the tunnel up with: sudo makimad"

update: stop
	@for b in $(BINS); do sudo rm -f $(BINDIR)/$$b; done
	@$(MAKE) --no-print-directory install
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
# Kept out of `make` on purpose. It needs Rust, bun and — on Linux — GTK and
# webkit2gtk, none of which the four binaries require, and somebody building a
# VPN from source should not have to install a UI toolchain to get one.
app:
	@cd desktop && bun install --frozen-lockfile && bun run tauri build

# The app against a pretend mesh, so the interface can be worked on without
# root and without a tunnel. Two processes; this runs the second.
app-dev:
	@echo "  run 'go run ./desktop/devserver' in another terminal first"
	@cd desktop && MAKIMA_GUI_SOCKET=/tmp/makima-dev.sock bun run tauri dev

release-clean:
	@rm -rf $(RELEASE)

clean: release-clean
	@rm -rf $(BUILD)
# Service units. Installed on request rather than by `make`, because a daemon
# that enables itself at boot on a machine somebody was only trying out is a
# surprise, and this one takes over an interface and the routing table.
service:
	@sh dist/install-service.sh
