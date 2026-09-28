<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# AGENTS.md

Architecture and conventions for agents working in this repository. Setup, build
and test commands are in [DEV.md](DEV.md); the product overview and security model
are in [README.md](README.md).

## Layout

| Path | What |
|---|---|
| `cmd/portitor-web` | GUI/API binary: `start`, `migrate`, `createadmin` |
| `cmd/portitor-agent` | Agent daemon on the firewall: `start`, `init`, `render`, `netns-exec` |
| `internal/fwconfig` | The desired-state document and `Validate()`. **The contract between web and agent.** |
| `internal/render` | Pure functions: document → nftables, WireGuard, named.conf, Kea, dnsmgr2 config |
| `internal/agent` | Agent: apply/reconcile, commit-confirm, DHCP client, IP lists, task scheduler, packet log (NFLOG), status, API server |
| `internal/dyndns` | Dynamic DNS client (RFC 2136, from ifnsupdate); the agent runs it per instance netns |
| `internal/iplist` | Downloads IP lists (CrowdSec LAPI decisions, plain-text lists) |
| `internal/cron` | crontab(5) schedule parser for tasks (shared by web and agent) |
| `internal/agentapi` | Agent API wire types (shared by agent and client) |
| `internal/agentclient` | portitor-web's HTTPS client for the agent, with certificate pinning |
| `internal/builder` | Database → `fwconfig.Document` (resolves ids, IPAM, DHCP scopes, DNS names) |
| `internal/ipam` | Prefix tree by CIDR containment, next free address |
| `internal/netobj` | Named hosts/prefixes (`address_objects`): name checks and expansion |
| `internal/dbmigrate` | Opens the SQLite database; goose migrations (the schema's source of truth) |
| `models` | GORM mapping |
| `web` | Echo v5 server: auth, generic CRUD (`crud.go`), entry validation (`resources.go`), deploy handlers |
| `web/frontend` | Vue SPA; `CrudPage.vue` drives most pages from field/column schemas |
| `docs` | User guides; every `docs/*.md` is bundled into the GUI's Help page (`src/docs.js`), and links between them stay in the GUI |
| `deploy` | systemd units and example configs |
| `dev` | Dev configs and `seed.sh`; `dev/lab` runs a real apply in two podman containers |
| `install.py` | Installs/updates web and agent from a GitHub release (`.goreleaser.yaml`), `--source` or `--local`; the agent runs its copy in `/usr/lib/portitor` for GUI updates |
| `iso` | Installer ISO: Debian netinst + preseed (`build.sh`), first-boot setup (`firstboot.py`, runs `portitor-web bootstrap`), QEMU test VM (`vm.sh`) |

## Invariants

- **The agent trusts nothing.** It re-runs `fwconfig.Validate` before rendering.
  Anything that ends up in a config file must be validated there: names by regex,
  addresses by `netip`, comments without control characters. nft strings cannot
  escape quotes, so `render.comment` replaces them.
- **Rendering is pure** (no I/O) so the preview is exactly what apply writes. Don't
  put volatile data (timestamps, generation) in rendered files; unchanged config must
  render byte-identical. Downloaded IP list contents are volatile: the ruleset only
  declares the sets and `include`s the list's elements file
  (`<state_dir>/iplists/<name>.nft`), which the agent writes on download and creates
  empty before a ruleset that includes it is checked or loaded.
- **All system changes go through `agent.Runner`** (exec, dry-run, or fakes in
  tests). Reconcile logic is planned as pure functions over parsed `ip -j` output
  (`netstate.go`) and unit-tested that way.
- **The agent owns** the `inet firewall` table in each namespace, every `fw-*`
  namespace, routes with `proto 99`, and root-namespace virtual interfaces listed in
  `managed.json`. Leave everything else alone (docker, libvirt, other tables).
  Accept rules set the connection mark (`ct mark`) to the rule's id, so the
  rule counters (`render.RuleCounter`) count whole connections; the agent owns
  `ct mark` in its namespaces. Log statements send to nflog group
  `render.LogGroup`, never the kernel log, with a prefix `render.ParseLogPrefix`
  reads; the agent listens on that group in each namespace whose ruleset logs.
- **Commit-confirm:** the rollback target is the last *confirmed* document; a second
  apply while one is pending keeps it. `rollback.json` makes a pending change roll
  back after an agent restart too.
- **Secrets:** fields tagged `json:"-"` (WireGuard private/preshared keys, TSIG
  secrets, IP list passwords and API keys, agent token, password hashes) never reach
  the browser. The generic CRUD
  `PUT` merges the body onto the stored row, so those fields can't be overwritten
  through the API either; a secret the user enters comes in through a write-only
  `gorm:"-"` field that `prepare` copies and `present` clears (`DyndnsClient.NewTsigSecret`,
  `IpList.NewPassword`/`NewApiKey`).
  Deployment history stores a redacted document.
- **Rules match interfaces by name.** Rule and NAT interface lists hold interface
  names (link ends included) and interface zone names of the instance; an
  interface zone is a group of zero or more interfaces. An empty list matches
  *any* interface, so a list must never lose entries silently: renaming an
  interface, link end or zone rewrites the lists (`web/ifzones.go`), deleting one
  that a rule uses is refused, and a non-empty list that resolves to no enabled
  interface (`Instance.MatchInterfaces`) makes the renderer skip the rule.
- **Named hosts/prefixes never reach the agent.** `builder.Build` expands names
  (`netobj`) and drops a rule it cannot resolve; an object with no addresses is an
  error, never an empty list (an empty address list matches *any*). Entries are
  stored by name, so renaming an object rewrites them (`web/objects.go`) and deleting
  one in use is refused. A new address field that should accept names must be added
  to `eachObjectRef` and expanded in the builder.
- **IP lists reach the agent as references.** A filter rule's address list may hold
  `@name` (not NAT, not other address fields): it matches either IP version and
  renders as the list's `name_v4`/`name_v6` set. One nft match takes one operand, so a
  list with literals and IP lists renders one rule per operand. Renaming a list
  rewrites the rules (`web/tasks.go`); deleting one a rule or task uses is refused.
- **Dual stack:** rule and NAT address lists may mix IPv4 and IPv6;
  `fwconfig.MatchFamilies` decides which versions a rule is rendered for, and
  validation uses the same function.
- **Schema changes:** a new goose file in `internal/dbmigrate/sql/` (SQLite), plus
  the model change. Tests run the real migrations, with foreign keys enforced as in
  production; a test checks every model field has a column. SQLite's `ALTER TABLE`
  only adds, drops and renames columns; anything else rebuilds the table (create,
  copy, drop, rename) in a `-- +goose NO TRANSACTION` migration that turns
  `foreign_keys` off around it. Ids are `AUTOINCREMENT` so a deleted row's id is
  never reused (rule ids mark connections).
- **Database files:** portitor-web refuses to run as root against a database
  directory owned by another user; root would leave root-owned `-wal`/`-shm` files.
  Scripts run it as the service user (`runuser -u portitor --`).
- **Updates from the GUI** (`internal/agent/system.go`): the Debian upgrade and the
  Portitor update run as transient systemd units (`systemd-run`), never as children
  of the agent, because the update restarts the agent. The release tag is checked
  against a regex before it becomes an argument to `install.py`. `install.py
  --list --json` is the interface between agent and installer; keep its fields stable.

## Adding a feature end to end

1. Add fields to `fwconfig` and validate them in `validate.go` (with a test case).
2. Render them in `internal/render` (with a test; `nft -c` covers syntax).
3. Apply them in `internal/agent` if they need more than a file.
4. Migration + model, `builder.Build` mapping, entry checks in `web/resources.go`.
5. A page or fields in `web/frontend` (most pages are a `CrudPage` schema).

## Licence

AGPL-3.0-or-later. Every new file starts with the same two SPDX lines as the
existing ones, in its comment syntax, above any `//go:build` line and below any
shebang. Files that cannot hold a comment go in `REUSE.toml`. Commits carry a DCO
`Signed-off-by:` line (`git commit -s`); see [CONTRIBUTING.md](CONTRIBUTING.md).

## Gotchas

- Echo v5 handlers are `func(c *echo.Context) error`. Parse path ids with
  `echo.PathParam[uint]`, never pass the raw string to GORM (it becomes SQL).
- Kea 2.6+ only accepts lease files and control sockets in its own directories,
  hence `paths.kea_data_dir` / `kea_socket_dir`.
- DHCPv4 goes through dnsmgr2; DHCPv6 (`kea-dhcp6.conf`, reservations included) and
  radvd are rendered directly, because Kea6 needs each subnet's `interface`, which
  dnsmgr2 does not write.
- dnsmgr2 zones require a DNS host template, so DHCP reservations (made from A records
  with a MAC) need the instance's DNS server enabled. The builder reports this.
- DNS templates (SOA templates, DNSSEC policies, zone templates) are global in the
  database; `builder.Build` copies into each instance only the ones its zones use,
  and zones refer to them by name. A zone without a template gets the built-in
  localhost SOA/NS. dnsmgr2 writes only `dnssec-policy "<name>"`; the policy body
  is rendered into `named.conf`.
- Debian/Ubuntu confine named, Kea, kea-lfc (and `wg`) with AppArmor: a path outside the
  profile fails as "permission denied" despite the file mode, even as root.
  `install.py` adds `deploy/apparmor/<profile>` to `/etc/apparmor.d/local/<profile>`;
  a new path named or Kea reads or writes must be added there.
- `portitor-agent netns-exec` reads `<state_dir>/instances/<name>/netns`, written on
  apply; the per-instance systemd units start through it.
- `pkill -f portitor-web` also matches a shell whose command line contains that text;
  anchor the pattern (`pkill -f '^./build/portitor-web'`).
