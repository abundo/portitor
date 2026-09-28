<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Development

The web GUI's frontend is a Vue 3 SPA
that's either served from disk (dev) or embedded into the `portitor-web`
binary (release build, `-tags release`).

- Go 1.26+ (go.mod pins the `toolchain` that CI and releases build with; with the
  default `GOTOOLCHAIN=auto` an older local Go downloads it)
- Node.js 22.18+ or 24.12+

Schema migrations are a dedicated command: `portitor-web migrate`. `start` never
migrates.

GORM models (`models/`) are the application
mapping, not the source of schema.

goose is used for migrations: `internal/dbmigrate/sql/NNNNN_name.sql`. Add a new
file for every schema change and keep `models/` in step.

### Frontend stack

Vue 3, Vite, Vue Router, Pinia, Nuxt UI, Axios, Tailwind CSS 4. Linting via `oxlint` + `eslint`, formatting via `prettier`.

### Development setup

Everything runs on your workstation: the agent in
**dry-run** mode (renders files and logs the commands it would run; it writes only
its own state, such as the applied configuration and IP list downloads, under its
`state_dir`, so give it paths of its own), and the web GUI in dev mode.

```sh
make dev-agent         # terminal 1: dry-run agent on https://127.0.0.1:8443
make dev-web           # terminal 2: migrate, then GUI/API on http://127.0.0.1:8080
make dev-seed          # admin / dev-password-123, a sample home network, agent settings
cd web/frontend && npm install && npm run dev   # optional: Vite with hot reload on :5173
```

`dev/agent.yaml` and `dev/web.yaml` are the dev configs; runtime files (token,
certificate, rendered configs, agent state, logs, the SQLite database
`portitor.db`) go to `dev/run/`. Delete `dev/run/portitor.db*` for an empty database.

Render a document without an agent: `portitor-agent render --sample`, or
`portitor-agent render doc.json`.

### Tests

```sh
make test              # go test ./...
make lint              # go vet + oxlint + eslint (fixes in place)
make fmt               # gofmt + prettier; CI fails on unformatted files
```

- `internal/fwconfig`, `internal/render`: validation and rendering. The render
  tests also run the generated rulesets through real `nft -c` inside an
  unprivileged user namespace (`unshare -rn`), and skip when that isn't possible.
- `internal/agent`: reconcile planning against captured `ip -j` output, and the API
  (auth, apply, commit-confirm and timed rollback) in dry-run. `TestDyndnsInNetns`
  runs a dynamic DNS client in a real namespace; it needs root and opt-in:
  `PORTITOR_NETNS_TEST=1 unshare -rnm sh -c 'mount -t tmpfs none /run && go test -run InNetns ./internal/agent/'`.
- `internal/dyndns`: the dynamic DNS client against an in-memory nameserver, and
  TSIG against a real one on localhost.
- `internal/builder`, `web`: a temporary SQLite database with the real goose
  migrations and foreign keys enforced. `TestDeployEndToEnd` drives portitor-web against a real dry-run agent over
  TLS with certificate pinning.

Nothing in `make test` runs a real apply as root; the lab below does.

### Lab: a real apply in containers

`dev/lab/lab.sh` starts two systemd containers with rootless podman and installs
the release build in them, the way README's *Install* does on real machines:

```
            fwlab-wan 198.51.100.0/24              fwlab-lan 192.168.1.0/24
  mgmt ─────────────────────────────── fw ─────────────────────────────── mgmt, clients
  "ISP": dnsmasq DHCP, NAT      eth0 (DHCP client)  eth1 .1                lan0 .2
                                                    eth2 ── fwlab-guest 192.168.50.0/24 (instance guest)
```

- **fwlab-fw** runs `portitor-agent` as root and applies for real: nftables, the
  `fw-guest` namespace, VLAN, WireGuard, veth link, BIND and Kea.
- **fwlab-mgmt** runs `portitor-web`, reaches the agent over the LAN,
  and plays the ISP on the firewall's WAN (DHCP and NAT to the outside).

```sh
make lab-up       # images, containers, release build, install; GUI on http://127.0.0.1:28080, admin / admin
make lab-seed     # the dev/seed.sh network, agent settings
make lab-deploy   # apply (and confirm, when there is something to roll back to)
make lab-install  # after code changes: rebuild and reinstall both binaries
dev/lab/lab.sh client      # a throwaway LAN host with a DHCP lease from the firewall
dev/lab/lab.sh shell fw    # or mgmt; `logs fw|mgmt` follows the journals
make lab-down     # remove containers and networks
```

The lab networks have no podman IPAM: addresses come from the agent, dnsmasq, Kea
or `portitor-lab-net.service` (the LAN address the agent listens on before the first
deploy). `LAB_WEB_PORT` changes the published GUI port. Rootless is enough because
`--privileged` stays inside the user namespace. It needs the `wireguard` kernel
module loaded on the host for `wg0`.

### Releases and install.py

Before tagging: `make test`, `make lint`, `make fmt` leave nothing to commit, and
`go run golang.org/x/vuln/cmd/govulncheck@latest ./...` reports nothing your code
calls. For a vulnerability in the standard library, raise `toolchain` in go.mod.

Pushing a tag `v*` runs `.github/workflows/release.yml`: tests, then GoReleaser
(`.goreleaser.yaml`) publishes `portitor_<version>_linux_{amd64,arm64}.tar.gz` (both
binaries, `deploy/`, `install.py`) and a checksums file. The `iso` job then builds
the installer ISO from the published amd64 archive (`iso/build.sh --release`) and
attaches `portitor-<tag>-amd64.iso` and its `.sha256` to the release. `install.py` installs from
those. Bump `INSTALLER_VERSION` in it whenever the installer changes: a release's copy
runs the install unless the running copy's version is higher, and a standalone copy
updates itself from the latest release.

From a checkout, `./install.py --source` builds (`make release`, CGO off) and installs
`build/` the same way; add `--dry-run` to see what would change, `--agent HOST` to
target a firewall. A remote agent of another architecture gets a cross-built binary.

`--local PATH` installs a release archive or an extracted release directory without
GitHub (the ISO uses it). `--list --json` is what the agent runs for *Admin → Updates*;
`--install TAG --yes --skip-self-update` is what it runs, in the transient unit
`portitor-update`, to install one.

### Installer ISO

`iso/build.sh` remasters the Debian 13 netinst ISO with xorriso: `preseed.cfg`, new
boot menus (`grub.cfg` for UEFI, `isolinux.cfg` for BIOS), and `/portitor` with the
release archive, `late.sh`/`target.sh` (run at the end of the installation) and the
first-boot setup `portitor-setup.py`. See [docs/appliance.md](docs/appliance.md).

To try it end to end without any typing:

```sh
iso/build.sh --test
VM_SERIAL=build/vm-install.log iso/vm.sh install build/portitor-<version>-test-amd64.iso
VM_SERIAL=build/vm.log iso/vm.sh run &
curl -k https://127.0.0.1:28443/api/version    # after a minute or two
```

Log in to the GUI as `admin` / `portitor-test`. Without `VM_SERIAL` the serial
console is on stdio; after the first boot you can log in there as `portitor`.
`VM_UEFI=1` boots with OVMF.
