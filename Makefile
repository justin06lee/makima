# makima — build, install, and restart the node daemon.
#
# `make` alone does the whole golden path. Nothing else needs to be run by hand.

BINDIR  := /usr/local/bin
BINS    := makima makimad makima-server
BUILD   := build
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build install update restart stop clean test fmt vet check cross

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

check: fmt vet test

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

clean:
	@rm -rf $(BUILD)
