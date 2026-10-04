# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

BUILD_DIR := build
PREFIX    := /usr

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse HEAD 2>/dev/null || echo none)
DATE    := $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
LDFLAGS := -s -w \
	-X github.com/abundo/portitor/internal/buildinfo.Version=$(VERSION) \
	-X github.com/abundo/portitor/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/abundo/portitor/internal/buildinfo.Date=$(DATE)


.PHONY: build portitor-web portitor-agent frontend release test lint fmt \
	install-agent install-web dev-agent dev-web dev-seed \
	lab-up lab-install lab-seed lab-deploy lab-down iso iso-test iso-e2e clean

build: portitor-web portitor-agent

portitor-web portitor-agent:
	go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$@ ./cmd/$@

frontend:
	cd web/frontend && npm ci && npm run build

# Self-contained portitor-web with the frontend embedded.
release: frontend
	go build -tags release -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/portitor-web ./cmd/portitor-web
	go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/portitor-agent ./cmd/portitor-agent

test:
	go test ./...

lint:
	go vet ./...
	cd web/frontend && npm run lint

fmt:
	gofmt -w cmd internal models web/*.go
	cd web/frontend && npm run format

# ----- install (run as root) -----

install-agent: portitor-agent
	install -D -m 0755 $(BUILD_DIR)/portitor-agent $(DESTDIR)$(PREFIX)/bin/portitor-agent
	ln -sfn portitor-agent $(DESTDIR)$(PREFIX)/bin/portitor
	install -D -m 0644 deploy/systemd/portitor-agent.service $(DESTDIR)/etc/systemd/system/portitor-agent.service
	install -D -m 0644 deploy/systemd/portitor-named@.service $(DESTDIR)/etc/systemd/system/portitor-named@.service
	install -D -m 0644 deploy/systemd/portitor-kea4@.service $(DESTDIR)/etc/systemd/system/portitor-kea4@.service
	install -D -m 0644 deploy/systemd/portitor-kea6@.service $(DESTDIR)/etc/systemd/system/portitor-kea6@.service
	install -D -m 0644 deploy/systemd/portitor-radvd@.service $(DESTDIR)/etc/systemd/system/portitor-radvd@.service
	install -D -m 0644 deploy/systemd/portitor-frr@.service $(DESTDIR)/etc/systemd/system/portitor-frr@.service
	test -e $(DESTDIR)/etc/portitor/agent.yaml || install -D -m 0600 deploy/agent.yaml $(DESTDIR)/etc/portitor/agent.yaml

install-web: release
	install -D -m 0755 $(BUILD_DIR)/portitor-web $(DESTDIR)$(PREFIX)/bin/portitor-web
	install -D -m 0644 deploy/systemd/portitor-web.service $(DESTDIR)/etc/systemd/system/portitor-web.service
	test -e $(DESTDIR)/etc/portitor/web.yaml || install -D -m 0600 deploy/web.yaml $(DESTDIR)/etc/portitor/web.yaml

# ----- development: SQLite in dev/run + dry-run agent (see DEV.md) -----

dev-agent: portitor-agent
	@test -e dev/run/agent.token || $(BUILD_DIR)/portitor-agent init --host 127.0.0.1 \
		--token-file dev/run/agent.token --tls-cert dev/run/agent.crt --tls-key dev/run/agent.key
	$(BUILD_DIR)/portitor-agent -f dev/agent.yaml start

dev-web: portitor-web
	mkdir -p dev/run
	$(BUILD_DIR)/portitor-web -f dev/web.yaml migrate
	$(BUILD_DIR)/portitor-web -f dev/web.yaml start

dev-seed: portitor-web
	echo 'dev-password-123' | $(BUILD_DIR)/portitor-web -f dev/web.yaml createadmin admin
	dev/seed.sh

# ----- lab: real apply in two podman containers (see DEV.md) -----

lab-up lab-install lab-seed lab-deploy lab-down:
	dev/lab/lab.sh $(@:lab-%=%)

# ----- installer ISO from this tree (see DEV.md); build.sh runs make release -----

iso:
	iso/build.sh

# Unattended: erases /dev/vda without asking. For iso/vm.sh only, never real hardware.
iso-test:
	iso/build.sh --test

# Builds a test ISO, installs it in iso/vm.sh's virtual machine and checks the
# first-boot setup (20-40 minutes). KEEP=1 leaves the VM running.
iso-e2e:
	iso/test.sh

clean:
	rm -rf $(BUILD_DIR)
