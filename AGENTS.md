<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# AGENTS.md

Architecture and conventions for agents working in this repository. Setup, build
and test commands are in [DEV.md](DEV.md); the product overview and security model
are in [README.md](README.md).

## Layout

| Path | What |
|---|---|
| `cmd/portitor-web` | GUI/API binary: `start`, `migrate`, `createadmin`, `agent-url`, `bootstrap` (ISO first boot) |
| `cmd/portitor-agent` | Agent daemon on the firewall: `start`, `init`, `render`, `netns-exec`; run as `portitor` (a symlink, `cli.go`) it is a read-only CLI (`show lldp neighbours`, `show ip neighbours`) over the agent's GET routes on the root-only socket `<run_dir>/agent.sock` |
| `internal/fwconfig` | The desired-state document and `Validate()`. **The contract between web and agent.** |
| `internal/render` | Pure functions: document → nftables, WireGuard, named.conf, Kea, chrony.conf (`chrony.go`), dnsmgr2 config, FRR (`frr.go`: frr.conf with BGP, OSPF, VRRP and BFD, daemons, vtysh.conf) |
| `internal/agent` | Agent: apply/reconcile, commit-confirm, DHCP and DHCPv6 (prefix delegation) clients, IP lists, task scheduler, packet log (NFLOG), DNS query log (BIND logs to the journal, followed with `journalctl`, filtered by the agent, `querylog.go`), WireGuard endpoint re-resolving, packet capture (tcpdump, streamed rate-limited), traceroute (`mtr --raw`, streamed as JSON lines, `trace.go`), LLDP (sent and heard on raw sockets, `lldp.go`), neighbours (ARP/ND, LLDP), NAT64 (a Jool instance per namespace, `nat64.go`), traffic shaping (CAKE, IFB devices for receiving, HTB classes for the rate limits that shape (`fwconfig.Instance.Shapers`) by packet mark `render.ShaperMark`; planned from `tc -j` output, `shaping.go`), BGP, OSPF, VRRP and BFD state (FRR's JSON through `vtysh`, `bgp.go`, `ospf.go`, `vrrp.go`, `bfd.go`), VRRP's macvlan devices (`vrrp.go`), status, API server |
| `internal/dyndns` | DNS update client ("DNS update" in the GUI): RFC 2136 (from ifnsupdate), sent from the instance netns, or a DNS hosting provider's API through libdns (`providers.go`, matching `fwconfig.DNSProviders`), called from the host |
| `internal/acme` | ACME certificates through lego: accounts, orders, the stored chain and key (`<state_dir>/certificates/`); the agent's `acme.go` schedules them and answers HTTP-01 in the instance netns, opening port 80 by the `acme_http` set (`render.ACMEHTTPSet`) |
| `internal/nftimport` | nftables file (`nft -j list ruleset`, read by the agent's `POST /v1/nftables/parse` in a new network namespace, `nftparse.go`) → rules, NAT rules, hosts/prefixes, services, and what it leaves out, with jumped-to chains inlined in groups; written by `web/nftimport.go` through the CRUD's `prepare*` checks, a preview being the same transaction rolled back |
| `internal/iplist` | Downloads IP lists (CrowdSec LAPI decisions, plain-text lists) |
| `internal/wgkeys` | WireGuard key generation (wg(8) base64) |
| `internal/buildinfo` | Version, commit and date, set at link time (Makefile `LDFLAGS`, `.goreleaser.yaml`) |
| `internal/cron` | crontab(5) schedule parser for tasks (shared by web and agent) |
| `internal/agentapi` | Agent API wire types (shared by agent and client) |
| `internal/agentclient` | portitor-web's HTTPS client for the agent, with certificate pinning |
| `internal/builder` | Database → `fwconfig.Document` (resolves ids, IPAM, DHCP scopes, DNS names) |
| `internal/ipam` | Prefix tree by CIDR containment, next free address |
| `internal/netobj` | Named hosts/prefixes (`address_objects`) and address lists (`address_lists`): name checks and expansion |
| `internal/dbmigrate` | Opens the SQLite database; goose migrations (the schema's source of truth) |
| `models` | GORM mapping |
| `web` | Echo v5 server (`server.go`: routes): auth, generic CRUD (`crud.go`), entry validation (`resources.go`), deploy handlers (`handlers.go`), Revert snapshots (`revert.go`), tenancy (`tenancy.go`), roles (`roles.go`, `access.go`), rename/delete reference keeping (`objects.go`, `services.go`, `ratelimits.go`, `ifzones.go`, `bgp.go`, `ospf.go`, `vrrp.go`, `bfd.go`, `delegated.go`), folders for hosts and IP lists (`folders.go`, GUI only), agent proxies (`console.go`, `capture.go`, `trace.go`, `connections.go`), WireGuard config import (`wgimport.go`), backup/restore (`backup.go`), `web.yaml` (`config.go`) |
| `web/frontend` | Vue SPA; `CrudPage.vue` drives most pages from field/column schemas |
| `docs` | User guides; every `docs/*.md` is bundled into the GUI's Help page (`src/docs.js`), and links between them stay in the GUI |
| `deploy` | systemd units and example configs |
| `dev` | Dev configs and `seed.sh`; `dev/lab` runs a real apply in two podman containers |
| `install.py` | Installs/updates web and agent from a GitHub release (`.goreleaser.yaml`), `--source` or `--local`; the agent runs its copy in `/usr/lib/portitor` for GUI updates |
| `iso` | Installer ISO: Debian netinst + preseed (`build.sh`), setup (`portitor-setup.py`, installed as `portitor-setup`: runs `portitor-web bootstrap` at first boot, `--reconfigure` when run again; or sets up only the agent, which prints a join string, or only portitor-web, which deploys it with `bootstrap --join`), QEMU test VM (`vm.sh`), end-to-end test (`test.sh`, `make iso-e2e`) |

## Terms

An *instance* (code, API, database) is a **virtual firewall** (short **VF**) in the GUI,
docs and user-facing messages.

## How it fits together

- **Two processes.** portitor-web owns the SQLite database and the GUI; the
  agent runs as root on the firewall and owns the system. They talk over the
  agent's HTTPS API (`internal/agent/server.go`, `/v1/...`; wire types in
  `agentapi`): a bearer token (`token_file` in `agent.yaml`) and a pinned
  certificate fingerprint (`agentclient.New`). On the firewall, the root-only
  socket `<run_dir>/agent.sock` serves the GET routes without the token
  (`localHandler`), for the `portitor` CLI. The join string (`web/join.go`)
  carries what portitor-web needs to reach an agent on another host.
- **Deploy ("commit" in the GUI)**: `web/handlers.go` `deploy` takes a database
  snapshot (`web/revert.go`), `buildDoc` (`web/tenancy.go`) runs
  `builder.Build` on it (merged into the live document for an instance
  admin), and the document goes to `POST /v1/apply` with a confirm timeout.
  `Generation` is the monotonic deploy id. The agent validates, renders
  (`render.Render` → `Bundle`), preflights (programs installed, `nft -c` on
  every ruleset), then `applyLocked` (`internal/agent/apply.go`) creates
  namespaces, loads rulesets, moves and configures interfaces, writes files and
  reloads or restarts the units whose files changed (`applyServices`,
  `applyFRR`). The browser then confirms
  (`/v1/confirm`) or the agent rolls back on timeout. `POST /v1/render` is the
  preview, with the same code and no apply. Only one change can be pending at a
  time (`deployMu`, and the agent is asked).
- **Revert** discards uncommitted database edits by restoring the live
  deployment's snapshot (`<db dir>/deployed/<gen>.db`); the newest
  `snapshotKeep` are kept. A document can't be turned back into rows.
- **Live data** (status, leases, neighbours, counters, logs) is fetched from the
  agent per request and filtered per tenant (`filter*` in `web/tenancy.go`).
  Logs are polled with `after` cursors from the agent's ring buffers
  (`logring.go`). Streams (capture, trace, connections) are proxied as
  they come, and the console is a WebSocket passed through both ways
  (`web/console.go`).
- **Frontend serving:** a dev build reads `web/static` from disk (`fs_dev.go`),
  so `npm run build` takes effect without a Go rebuild; `-tags release` embeds
  it (`fs_release.go`). Pinia stores (`stores/`): `auth`, `deploy` (polls the
  agent's status and rule counters, and the uncommitted changes, which a write
  rechecks through `changed()`), `instances` (the selected VF), `objects`.

## Invariants

- **The agent trusts nothing.** It re-runs `fwconfig.Validate` before rendering.
  Anything that ends up in a config file must be validated there: names by regex,
  addresses by `netip`, comments without control characters. nft strings cannot
  escape quotes, so `render.comment` replaces them.
- **Rendering is pure** (no I/O) so the preview is exactly what apply writes. Don't
  put volatile data (timestamps, generation) in rendered files; unchanged config must
  render byte-identical. Downloaded IP list contents are volatile: the ruleset only
  declares the sets and `include`s the list's elements file
  (`<state_dir>/iplists/<key>.nft`, `render.IPListKey`), which the agent writes on download and creates
  empty before a ruleset that includes it is checked or loaded.
- **All commands that change the system go through `agent.Runner`** (exec, dry-run,
  or fakes in tests); a dry run, like exec, refuses a finished context. Reconcile
  logic is planned as pure functions over parsed `ip -j` output (`netstate.go`) and
  unit-tested that way. Outside the Runner: rendered files (`writeFile`, skipped in
  dry-run), the agent's own state under `state_dir` (written in dry-run too), and the
  console and command tasks, which start their processes directly.
- **Apply order:** each instance's ruleset is loaded right after its namespace
  exists, before interfaces move in or come up and before forwarding is turned on.
  Rules match interfaces by name (`iifname`), so they need not exist yet; only `lo`
  is matched by index.
- **Rule order in a chain:** established/related, invalid drop, loopback and
  essential ICMP, anti-lockout and the services' auto accepts
  (`render.AutoInputRules`; BGP's from its neighbours' addresses only, OSPF's on its
  non-passive interfaces; their sources are sets `render.AutoSetName`, which Hosts &
  prefixes lists read-only), then the user's rules; in forward, the accept of port
  forwards (`ct status dnat`) comes after the user's rules, so a rule can drop what a
  DNAT would let in; then the policy. The input auto accepts stay first so a rule
  that closes an interface to the firewall keeps the DHCP and DNS enabled on it.
  The output chain has auto accepts too, before the user's rules: the BGP sessions
  FRR opens to its neighbours (TCP 179), what OSPF sends (IP protocol 89,
  `render.OSPFOutputMatches`), VRRP's advertisements (IP protocol 112) and BFD's
  control packets (UDP 3784, on the interfaces with BFD).
- **The agent owns** the `inet firewall` table in each namespace, every `fw-*`
  namespace, routes with `proto 99`, root-namespace virtual interfaces listed in
  `managed.json`, and the root and ingress qdiscs of its instances' interfaces with
  their `ifb-<name>` devices (`fwconfig.IFBName`; interface names may not start
  with `ifb-`), and the VRRP macvlan devices (`fwconfig.VRRPDevices`; names may not
  start with `vrrp4-` or `vrrp6-`), and the Jool instance `fwconfig.JoolInstance` in
  each namespace. Leave everything else alone (docker, libvirt, other tables).
  Accept rules set the connection mark (`ct mark`) to the rule's id, so the
  rule counters (`render.RuleCounter`) count whole connections; the agent owns
  `ct mark` in its namespaces. Log statements send to nflog group
  `render.LogGroup`, never the kernel log, with a prefix `render.ParseLogPrefix`
  reads; the agent listens on that group in each namespace whose ruleset logs.
- **Commit-confirm:** the rollback target is the last *confirmed* document; a second
  apply while one is pending keeps it (portitor-web refuses one, the agent allows
  it). `rollback.json` is written before an apply with confirmation changes anything
  (the apply fails if it can't be), and removed only once the target is restored or
  the change confirmed: a crash or a failed rollback leaves it for the next start. A
  failed rollback keeps the change pending and retries. `RolledBack` means the
  restore succeeded; `RollbackErrors` says it didn't.
- **Secrets:** fields tagged `json:"-"` (WireGuard private/preshared keys, TSIG
  secrets, DNS update provider settings, IP list passwords and API keys, agent token, password hashes) never reach
  the browser. The generic CRUD
  `PUT` merges the body onto the stored row, so those fields can't be overwritten
  through the API either; a secret the user enters comes in through a write-only
  `gorm:"-"` field that `prepare` copies and `present` clears (`DyndnsClient.NewTsigSecret`,
  `IpList.NewPassword`/`NewApiKey`, `BgpPeerSettings.NewPassword` with
  `ClearPassword`, `OspfInterface.NewAuthKey` with `ClearAuthKey`, `Certificate.NewPrivKey` for an imported certificate; a DNS update provider's secret settings come in
  through `DyndnsClient.Settings`, where an empty one keeps the stored value).
  A BGP password or OSPF MD5 key is in frr.conf, so that is a `Secret` file
  `Bundle.Redacted` masks.
  Deployment history stores a redacted document. The exceptions are the backup
  download (`web/backup.go`): the whole database, age-encrypted with the user's
  passphrase; and a WireGuard peer's client config (`render.WireGuardClientConf`),
  with its generated private key and preshared key; and the agent's
`GET /v1/certificates/<instance>/<name>`, an ACME certificate with its key for
the certificate portitor-web serves, chosen under Settings
(`settings.web_certificate_id`, `web/tlscert.go`). API answers are
  `Cache-Control: no-store`. IP list credentials go over `http://` only to loopback
  (`fwconfig.PlainTextCredentials`, checked when saving), and a download never
  follows a redirect that would take them to another host or from https to http
  (`iplist.CheckRedirect`).
- **Rules match interfaces by name.** Rule and NAT interface lists hold interface
  names (link ends included) and interface zone names of the instance; an
  interface zone is a group of zero or more interfaces. An empty list matches
  *any* interface, so a list must never lose entries silently: renaming an
  interface, link end or zone rewrites the lists (`web/ifzones.go`), deleting one
  that a rule uses is refused, and a non-empty list that resolves to no enabled
  interface (`Instance.MatchInterfaces`) makes the renderer skip the rule. An
  interface matches its VRRP devices too (`Instance.AddVRRPDevices`, in
  `MatchInterfaces` and the auto rules): what is sent to a virtual router's MAC
  address arrives on its device.
- **Interface addresses** are on the interface (`interfaces.addresses`): CIDRs with a
  host part (`fwconfig.ParseInterfaceAddress`; any address of a /31, /32, /127,
  /128), unique within the instance. IPAM does not assign them; `ipam.Tree` lists
  them, and their prefixes, as `auto` nodes (id 0). A DHCP or RA prefix is served on
  the interface with an address of the same prefix.
- **Delegated addresses** (`fwconfig.Delegated`, `<wan0>:2000::1/64`) are relative
  to the prefix wan0's DHCPv6 client gets delegated, known only on the agent.
  They stay in the document; `render.Render` resolves them from
  `Options.Delegated` (`Document.ResolveDelegated`, which leaves out what is not
  delegated yet), so rendering stays pure in (document, options). A changed
  prefix applies the current document again (`Agent.onPDChange`). They are
  allowed in interface addresses and in RA prefixes and RDNSS (the builder adds
  an RA with SLAAC for each delegated /64); renaming the delegating interface
  rewrites them (`web/delegated.go`), deleting or moving it is refused.
- **Named hosts/prefixes never reach the agent.** `builder.Build` expands names
  (`netobj`) and drops a rule it cannot resolve; an object with no addresses is an
  error, never an empty list (an empty address list matches *any*). Entries are
  stored by name, so renaming an object rewrites them (`web/objects.go`) and deleting
  one in use is refused. A new address field that should accept names must be added
  to `eachObjectRef` and expanded in the builder.
- **Address lists** (`address_lists`, `web/objects.go`) hold addresses, CIDRs and
  names of hosts and other lists; they share one namespace with `address_objects`
  (`nameFree`), so any address field takes either by name, and `netobj.New(objs,
  lists...)` resolves both (a loop is an error). In a filter rule's source or
  destination the builder writes a list as `$name` and adds it, expanded, to
  `Instance.AddressSets`; the renderer declares one set per IP version
  (`render.AddressSetName`) and leaves out a version the list has nothing of
  (`dropEmptySets`). Anywhere else it is expanded like a host. Renaming one, or a
  host it holds, rewrites the entries (`eachObjectRef` visits the lists); deleting
  one in use is refused.
- **Services never reach the agent either.** A rule's `services` list names
  custom services (`services` table) and predefined ones (`netobj.Predefined`);
  `builder.Build` expands them into `fwconfig.ServiceMatch`es (tcp/udp/sctp
  ports, icmp/icmpv6 type and code, ip protocol number) and drops a rule it
  cannot resolve (an empty list matches *any* protocol). The renderer writes
  one nft rule per match and IP version (`fwconfig.Rule.Matches`). A custom
  name can't be a predefined one. Renaming one rewrites the rules
  (`web/services.go`); deleting one in use is refused. NAT keeps its own
  protocol and port list, with numbers, ranges and the built-in port names
  (`fwconfig.Services`), which the agent resolves.
- **IP lists reach the agent as references.** A filter rule's address list may hold
  `@name` (not NAT, not other address fields): it matches either IP version and
  renders as the list's `<key>_v4`/`<key>_v6` set (`render.IPListKey`: the name, or a hash of a name nft would not take). One nft match takes one operand, so a
  list with literals and IP lists renders one rule per operand. Renaming a list
  rewrites the rules (`web/tasks.go`); deleting one a rule or task uses is refused.
- **Routing objects and BGP** (`web/bgp.go`) are per instance: prefix lists, AS
  path and community lists and route maps (`route_*` tables, entries as JSON),
  `bgp_configs` (one per instance), peer groups and neighbours. They refer to each
  other by name, as FRR does: renaming one rewrites the references
  (`eachRoutingRef`), deleting one in use is refused, a row never moves to another
  instance, and a new reference field goes in `eachRoutingRef`. Off (the default),
  the builder leaves BGP out of the document; the objects are left out unless BGP
  or OSPF is on (`Instance.FRRRunning`), and with neither (nor VRRP or BFD) the agent stops FRR. A
  neighbour's update source may name an interface; renaming the interface
  rewrites it (`renameIfaceRefs`). FRR runs zebra, staticd, bgpd, ospfd, ospf6d, vrrpd and bfdd as the
  instance needs them (the daemons file); static routes stay the agent's (kernel
  routes), so "redistribute static" renders as `redistribute kernel`.
- **OSPF** (`web/ospf.go`) is per instance and version (2: OSPFv2, IPv4,
  `Instance.OSPF`; 3: OSPFv3, IPv6, `Instance.OSPF6`): `ospf_configs` (one per
  instance and version) and `ospf_interfaces`, by interface name (link ends
  included), which `renameIfaceRefs` rewrites and `refuseIfaceInUse` keeps from
  being deleted. Its route maps are in `eachRoutingRef`. Area ids are stored
  dotted. OSPFv2's network statements and interface areas are exclusive, as in
  FRR.
- **VRRP** (`web/vrrp.go`, `fwconfig/vrrp.go`) is per instance: `vrrp_routers`, on
  an interface by name (link ends included; `renameIfaceRefs` rewrites it,
  `refuseIfaceInUse` keeps it from being deleted), with IPv4 and IPv6 virtual
  addresses in the interface's static prefixes (IPv6 also link-local). FRR's vrrpd
  runs them (they start FRR, `Instance.FRRRunning`); the agent makes one macvlan
  device per virtual router and IP version (`fwconfig.VRRPDevices`: virtual MAC,
  the addresses as /32 or /128, random link-local), created protodown so vrrpd
  alone turns it on, and sets `arp_ignore` 1 on its interface
  (`internal/agent/vrrp.go`). A disabled row is shut down in FRR, not left out.
- **BFD** (`web/bfd.go`, `fwconfig/bfd.go`) is per instance: `bfd_interfaces`, by
  interface name (link ends included; `renameIfaceRefs` rewrites it, removing the
  interface removes it), each a bfdd profile (`fwconfig.BFDProfile`). Static routes,
  OSPF interfaces and BGP neighbours and peer groups have a `bfd` flag, used only on
  an interface with BFD (`Instance.RouteBFD`, `NeighborBFD`, `BFDOn`; a disabled row
  is left out, so it is the switch); a BGP neighbour gets its peer group's flag per
  neighbour, never on the group in frr.conf. A static route with BFD is staticd's
  (frr.conf `ip route ... bfd profile`, its metric the distance), not the agent's
  kernel route (`Instance.KernelRoutes`), so "redistribute static" then also renders
  `redistribute static`.
- **NAT64** (`fwconfig/nat64.go`): one prefix per instance, used by DNS64 (named.conf),
  PREF64 (radvd) and Jool. An interface's `xlat464` flag puts PREF64 and DHCPv4
  option 108 on it, and, with Jool, is where packets to the prefix may come in: Jool
  takes them at prerouting (dstnat + 25), before the forward chain, so the ruleset's
  `prerouting_nat64` chain (priority mangle) drops the rest. The agent makes Jool's
  instance again when the NAT64 differs from `<state>/nat64.json` or it isn't running
  (`planNAT64`).
- **NTP** (`fwconfig/ntp.go`, `render/chrony.go`): chrony per instance
  (`instances.ntp_*`), its servers JSON. The default instance's chrony.service sets
  the host's clock; a virtual firewall's `portitor-chrony@` runs `chronyd -x` (the
  clock is the host's; netns-exec drops CAP_SYS_TIME). It answers clients on the
  interfaces with `ntp_serve` (the auto input rule "ntp server", like
  `dns_listen`), of those the `ntp_allow` prefixes (chrony `allow`; names expanded
  by the builder, in `eachObjectRef`), or `allow all` when empty. chronyd can't
  reload: a changed chrony.conf restarts it. The NTP page's Info tab is `GET
  /v1/ntp` (`internal/agent/ntp.go`): chronyc on the host through each chronyd's
  command socket (`InstanceFiles.ChronySocket`, a VF's in
  `<run_dir>/chrony/<instance>`, made by the agent for the chrony user and
  mounted into that instance's unit alone).
- **Dual stack:** rule and NAT address lists may mix IPv4 and IPv6;
  `fwconfig.MatchFamilies` decides which versions a rule is rendered for, and
  validation uses the same function.
- **Schema changes:** a new goose file in `internal/dbmigrate/sql/` (SQLite), plus
  the model change. Tests run the real migrations, with foreign keys enforced as in
  production; a test checks every model field has a column. SQLite's `ALTER TABLE`
  only adds, drops and renames columns; anything else rebuilds the table (create,
  copy, drop, rename) in a `-- +goose NO TRANSACTION` migration that turns
  `foreign_keys` off around it. Ids are `AUTOINCREMENT` so a deleted row's id is
  never reused (rule ids mark connections). A data move SQL cannot compute (prefix
  containment, say) is a Go migration registered in `dbmigrate.provider`
  (`interface_addresses.go`).
- **Roles:** a user is `admin`, `viewer` or `none` (`models.RoleAdmin`/`RoleViewer`/
  `RoleNone`): global access. Roles (`roles`, `role_members`, `role_instances`) grant
  instances at a level (admin/viewer); each instance but the default has its own
  role, created, renamed and deleted with it (`web/roles.go`). `accessOf` (`web/access.go`) merges
  them; `requireRole` (`web/auth.go`) denies by default: everyone but a global admin
  gets GET routes except `viewerDenied` (and `tenantDenied` for `none`), and only
  the writes in `viewerWrites`, plus `tenantWrites` for an instance admin, whose
  handlers must check the instance (`allowInstance`). A CRUD `resource` with a
  `scope` filters lists and checks rows per instance; one without is shared (read by
  all, written by global admins). A new route is global-admin-only for writes
  automatically; a new GET of instance data must filter it, and one that hands out
  secrets must check the instance or go in `viewerDenied`. `TestViewerRole` sweeps
  every route, `TestTenancy` the instance checks. An instance admin's deploy merges
  their instances from the database into the live deployment's document
  (`web/tenancy.go`, `deployed/<gen>.json`); only a full deploy keeps a snapshot
  for Revert.
- **Database files:** portitor-web refuses to run as root against a database
  directory owned by another user; root would leave root-owned `-wal`/`-shm` files.
  Scripts run it as the service user (`runuser -u portitor --`).
- **Updates from the GUI** (`internal/agent/system.go`): the Debian upgrade and the
  Portitor update run as transient systemd units (`systemd-run`), never as children
  of the agent, because the update restarts the agent. The release tag is checked
  against a regex before it becomes an argument to `install.py`. `install.py
  --list --json` is the interface between agent and installer; keep its fields stable.
  An update installs the Debian packages in `install.py`'s `AGENT_PACKAGES` that are
  missing (masking their distribution units first); a release that needs a new
  package adds it there and to `iso/preseed.cfg`.
  BIND comes from ISC's Debian repository (`bind.debian.net/bind`, key in
  `deploy/apt/isc-bind.asc`): the ISO's preseed adds it (`apt-setup/local0`), an
  update adds it where the release has a suite (`add_bind_repo`).

## GUI design rules

Apply these to every page, `CrudPage` and custom pages alike. `CrudPage` does
them itself (give it a `noun` or `item-name` when the title doesn't make a good
singular); a custom page uses `SearchInput` above each table,
`useConfirm().confirmDelete` for the Yes / No prompt, `inlineField` / `wideModal`
(`utils/form.js`) for its dialog forms and `useFormGuard` for their Cancel and X.

- **Tables:** the Edit button is the first column, so it stays visible when the
  table is wider than the screen. Tables have no Delete button. The Edit button
  is `<UButton icon="i-lucide-pencil" variant="outline" size="sm" />` (with
  `i-lucide-eye` instead when read-only), in every table and data table.
- **Compact tables:** rows are dense so many fit on the screen. `UTable`'s cell
  padding is set once in `vite.config.js` (`ui.table.slots`: `th` `px-2 py-1.5`,
  `td` `px-2 py-1`); don't add padding back per table. A plain `<table>` uses
  `py-1` on its cells. `RulesTable` keeps its own grid styling.
- **Search:** every table (data tables included) has a search field above it that
  filters the rows as you type, with an X (cross) in the field that clears it:
  `SearchInput.vue`, with `useSearch` (`utils/search.js`) for the rows. A row
  matches when its shown text holds every word typed. `CrudPage` has one (give it
  `searchText` for a cell slot that shows more than the column's value); while
  searching, rows can't be dragged. A tree (Hosts & prefixes) shows the matches with
  the folders and prefixes above them, unfolded.
- **Delete** lives in the detail view (Edit → the form). It asks for confirmation
  and names what will be deleted ("Delete interface WAN (ens18)?"), with Yes / No.
- **Forms and dialogs** are wide when the screen allows: each label sits on the
  same row as its value. On a narrow screen they fall back to one column, with the
  label above the value.
- **Lists of entries** with several fields (a prefix list's entries, BGP networks)
  are edited in place in the form with `EntriesEditor.vue`, one row per entry with
  a remove button (and up/down where order decides); route map entries, which
  have many fields, with `RouteMapEntries.vue`: Edit opens an entry's own dialog,
  which holds its Delete. A select that may name nothing uses `NameSelect.vue`
  (`''` is none), or a `CrudPage` field `nullable` with `text: true`.
- **Lists of values** (addresses, names) are entered as tags with
  `TagsInput.vue` (a `CrudPage` field `type: 'tags'`), never `UInputTags`
  directly: a click on a tag puts it back in the input to edit, and Enter or
  leaving the field returns it to its place.
- **Picking from a known set** (an interface zone's interfaces) uses the dual
  listbox `TransferList.vue` (a `CrudPage` field `type: 'transfer'`): Available
  and Selected, moved with the arrow buttons, a double-click or drag and drop.
- **Dialogs don't close by accident:** every `UModal` has `:dismissible="false"`,
  so a click outside it (or Escape) never closes it; only its buttons and X do. A
  form's Cancel and X go through `useFormGuard` (`composables/useFormGuard.js`),
  which asks "Discard them?" with Yes / No when the form has unsaved changes.
- **Unsaved changes are never lost silently:** every form registers with
  `composables/useFormGuard.js` (`useFormGuard` for a dialog, `usePageForm` or
  `useUnsaved` for a form on the page). Leaving the page (a router guard),
  switching instance and logging out ask the same question first
  (`confirmDiscard`); closing or reloading the tab gets the browser's warning.
- **Exceptions:** the rules list (`RulesTable`: a click opens the rule, the
  context menu deletes) and the DNS zone records grid (`ZoneRecordsTable`: edited
  in place, no detail view) are exempt from the table rules, and so is the
  packet capture's packet list (`PacketList`: Wireshark's display filter
  takes the search field's place), and so is the Hosts & prefixes tree
  (`ObjectTree`, a Wunderbaum treegrid: a click opens the row's form, the
  context menu adds). The rule's form is
  not: it follows the form and delete rules.

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
Committing directly to `main` is fine; no feature branch is needed.

## Gotchas

- Echo v5 handlers are `func(c *echo.Context) error`. Parse path ids with
  `echo.PathParam[uint]`, never pass the raw string to GORM (it becomes SQL).
- Kea 2.6+ only accepts lease files and control sockets in its own directories,
  hence `paths.kea_data_dir` / `kea_socket_dir`. Each virtual firewall's Kea units mount
  `<kea_data_dir>/<instance>` and `<kea_socket_dir>/<instance>` over them, so the
  rendered config names Kea's view (`InstanceFiles.Kea4Lease`) and the agent reads
  the host's (`InstanceFiles.KeaData`). named does the same with
  `paths.bind_cache_dir` (its working directory) and `bind_run_dir`; its zone
  files are in `<bind_zones_dir>/<instance>` (`InstanceFiles.BindZones`) at the same
  path on the host and for named, because dnsmgr2 writes their paths into
  `named.conf.dnsmgr2` on the host (a tmpfs hides the other instances').
  `install.py` moves older files in (`move_kea_leases`, `move_bind_dirs`). Kea's and radvd's PID files are in the unit's private
  /tmp: under `PrivatePIDs` the daemon is always PID 1, so a stale one would read
  as already running.
- **The default instance is the host, laid out like one.** Its files are in the
  distribution's standard places (`/etc/nftables.d/portitor.nft`, `/etc/wireguard`,
  `/etc/bind/named.conf`, `/etc/kea`, `/etc/radvd.conf`, Kea's and named's own
  directories without a subdirectory) and run by the distribution's units
  (`named`, `kea-dhcp4-server`, ...; `units.default_*`), which the agent unmasks
  when it uses them. Every path comes from `render.Paths.Files(instance)` and
  every unit from `render.Units`; never build them from `InstanceEtc`. Rendered
  files start with "Generated by portitor-agent" (`render.Generated`): a file of
  someone else's that one replaces is kept as `<file>.portitor-orig`, a
  distribution unit is stopped only while it runs from our file, and only our
  stale WireGuard configs are removed from `/etc/wireguard`. A default instance
  from before this layout is moved on apply (`Agent.moveDefaultInstance`). The
  GUI doesn't list it under Virtual firewalls; it is the first instance, its
  flag never moves and it can't be deleted (`prepareInstance`, `deleteInstance`).
- dnsmgr2 does DNS only. Kea (`render/kea.go`: `kea-dhcp4.conf`, `kea-dhcp6.conf`,
  reservations from A/AAAA records with a MAC included) and radvd are rendered
  directly: the DHCP subnets of one IP version on an interface form a Kea shared
  network named after it, so clients get addresses from all of them, and Kea6 needs
  each subnet's `interface`; dnsmgr2 writes neither. Subnet ids follow the prefixes
  sorted as text, as dnsmgr2 numbered them. Kea refuses a config that names an
  interface that is missing.
- DNS templates (SOA templates, DNSSEC policies, zone templates) belong to an
  instance (`instance_id`); the default instance's may be `global`, read by all and
  used by any instance's zones and templates, changed only by its own admins
  (`globalScope` in `web/access.go`, checks in `dnsOwner`/`usableBy`,
  `web/resources.go`). A global template needs a global SOA and policy, one in use
  elsewhere stays global, and names are unique per instance and a global one's
  across all, since the builder copies into each instance only the ones its zones
  use, and zones refer to them by name. A zone without a template gets the built-in
  localhost SOA/NS. dnsmgr2 writes only `dnssec-policy "<name>"`; the policy body
  is rendered into `named.conf`.
- Debian/Ubuntu confine named, Kea, kea-lfc (and `wg`) with AppArmor: a path outside the
  profile fails as "permission denied" despite the file mode, even as root.
  `install.py` adds `deploy/apparmor/<profile>` to `/etc/apparmor.d/local/<profile>`;
  a new path named or Kea reads or writes must be added there.
- `portitor-agent netns-exec` reads `<state_dir>/instances/<name>/netns`, written on
  apply; the per-instance systemd units start through it. It enters the namespace itself and
  drops CAP_SYS_ADMIN and the like (`droppedCaps`) before the exec, so a daemon
  can't setns into another instance. FRR is the exception
  (`netns-exec --keep-sys-admin`, `portitor-frr@.service`): zebra and bgpd refuse to
  start without CAP_SYS_ADMIN; they run as the frr user from the validated
  frr.conf. FRR forks, so its unit has no `PrivatePIDs`; it runs with the instance
  as FRR's pathspace (`/etc/frr/<instance>`, `vtysh -N <instance>`). The units are sandboxed per instance
  (multitenancy): they see only their own `etc`/`state` instance directories
  (`TemporaryFileSystem` + `Bind*Paths`), the rest read-only, with private
  /tmp, IPC and PID namespaces. A new path a daemon writes goes in its unit's
  `ReadWritePaths`; `ExecReload` needs the `+` prefix, as `PrivatePIDs` gives
  each `Exec*` line its own PID namespace.
- The packet capture page runs Wiregasm (Wireshark in WebAssembly) in a worker,
  `workers/capture.worker.js`, which fetches the capture stream itself and
  dissects the whole file again as it grows (Wiregasm has no incremental
  API), up to the last complete pcap record. Wiregasm (GPL-2.0) is a separate
  program, never bundled or embedded: portitor-web serves it at `/wiregasm/`
  from `wiregasm_dir`, where `install.py` downloads the pinned npm package
  (`WIREGASM_VERSION`/`WIREGASM_SHA512`, same as `package-lock.json`,
  `TestWiregasmPin`); in dev, Vite and portitor-web serve `node_modules`' copy. The worker script alone
  gets a CSP with `unsafe-eval` and `wasm-unsafe-eval` (`captureWorkerCSP`).
- `pkill -f portitor-web` also matches a shell whose command line contains that text;
  anchor the pattern (`pkill -f '^./build/portitor-web'`).
