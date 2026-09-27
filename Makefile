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

# Container runtime for the dev database.
RT := $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
DEV_PG     := portitor-dev-pg

.PHONY: build portitor-web portitor-agent frontend release test lint fmt \
	install-agent install-web dev-db dev-db-rm dev-agent dev-web dev-seed \
	lab-up lab-install lab-seed lab-deploy lab-down clean

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
	install -D -m 0644 deploy/systemd/portitor-agent.service $(DESTDIR)/etc/systemd/system/portitor-agent.service
	install -D -m 0644 deploy/systemd/portitor-named@.service $(DESTDIR)/etc/systemd/system/portitor-named@.service
	install -D -m 0644 deploy/systemd/portitor-kea4@.service $(DESTDIR)/etc/systemd/system/portitor-kea4@.service
	install -D -m 0644 deploy/systemd/portitor-kea6@.service $(DESTDIR)/etc/systemd/system/portitor-kea6@.service
	install -D -m 0644 deploy/systemd/portitor-radvd@.service $(DESTDIR)/etc/systemd/system/portitor-radvd@.service
	test -e $(DESTDIR)/etc/portitor/agent.yaml || install -D -m 0600 deploy/agent.yaml $(DESTDIR)/etc/portitor/agent.yaml

install-web: release
	install -D -m 0755 $(BUILD_DIR)/portitor-web $(DESTDIR)$(PREFIX)/bin/portitor-web
	install -D -m 0644 deploy/systemd/portitor-web.service $(DESTDIR)/etc/systemd/system/portitor-web.service
	test -e $(DESTDIR)/etc/portitor/web.yaml || install -D -m 0600 deploy/web.yaml $(DESTDIR)/etc/portitor/web.yaml

# ----- development: throwaway Postgres + dry-run agent (see DEV.md) -----

dev-db:
	@$(RT) inspect $(DEV_PG) >/dev/null 2>&1 && $(RT) start $(DEV_PG) >/dev/null \
		|| $(RT) run -d --name $(DEV_PG) -e POSTGRES_USER=portitor -e POSTGRES_PASSWORD=portitor-dev \
			-e POSTGRES_DB=portitor -p 127.0.0.1:55432:5432 docker.io/library/postgres:18-alpine >/dev/null
	@until $(RT) exec $(DEV_PG) pg_isready -U portitor >/dev/null 2>&1; do sleep 1; done
	@echo "postgres ready on 127.0.0.1:55432"

dev-db-rm:
	$(RT) rm -f $(DEV_PG)

dev-agent: portitor-agent
	@test -e dev/run/agent.token || $(BUILD_DIR)/portitor-agent init --host 127.0.0.1 \
		--token-file dev/run/agent.token --tls-cert dev/run/agent.crt --tls-key dev/run/agent.key
	$(BUILD_DIR)/portitor-agent -f dev/agent.yaml start

dev-web: portitor-web
	$(BUILD_DIR)/portitor-web -f dev/web.yaml migrate
	$(BUILD_DIR)/portitor-web -f dev/web.yaml start

dev-seed: portitor-web
	echo 'dev-password-123' | $(BUILD_DIR)/portitor-web -f dev/web.yaml createadmin admin
	dev/seed.sh

# ----- lab: real apply in two podman containers (see DEV.md) -----

lab-up lab-install lab-seed lab-deploy lab-down:
	dev/lab/lab.sh $(@:lab-%=%)

clean:
	rm -rf $(BUILD_DIR)
