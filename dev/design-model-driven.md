<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Design: a model-driven configuration

Status: phases 1 to 5 implemented; the configuration tables gone (step G), 2026-11-09. There are no production systems, so no
migration is planned beyond what portitor-config does itself.

## Goals

- One definition of the configuration, the YANG modules in `yang/`, from which every
  frontend works: the CLI, NETCONF, the API and the GUI, and SNMP for state (read
  only). A feature defined there is in every frontend.
- A tree datastore with a candidate, running and commits, as in SR Linux and SR OS.
- A CLI in the style of SR Linux and SR OS's MD-CLI, over the console and SSH.

Not goals: SNMP writes, private candidates per session (the candidate is shared, as
SR Linux's `candidate shared`), and the agent, `fwconfig` and `render`, which don't
change: the document stays the contract between portitor-config and the agent.

## The pieces

| Piece | Where | Does |
|---|---|---|
| YANG modules | `yang/` | the schema: module `portitor`, submodules by area, extensions `portitor-extensions` |
| Schema | `internal/schema` | compiles the modules (goyang) into the tree the frontends walk: kinds, keys, order, types, defaults, descriptions, extensions |
| Datastore | `internal/datastore` | the configuration as a tree: set, delete, rename (rewriting references), move, validate, JSON (RFC 7951), diff, patch; the shared candidate (`Store`) |
| Rows | `internal/datastore/sqlmap`, `internal/confview` | the tree as rows (the `px:` mapping), decoded into the models, for the builder and the code of before the tree; entries from rows for the imports (`Adder`); the entries' ids kept by path (`config_ids`) |
| NETCONF | `internal/netconf` | the NETCONF server on the datastore: framing, XML, edit-config, subtree filters, commit, locks, get-schema |
| CLI | `internal/cli` | the command line, its help and completion from the schema; the terminal, scripts and the SSH server |
| State | `yang/portitor-state.yang`, `web/state.go` | the live data as `config false` YANG, from the API's live views |
| Backend | `web/datastore.go` | the candidate (`candidate.json`), Running (the live commit's configuration), Commit (deploy); access by role; SSH logins |

## The phases

1. **Done.** YANG modules for all the configuration (617 leaves), schema, datastore,
   SQL bridge, CLI over the console and SSH, commit through the existing deploy. The
   GUI and API are unchanged.
2. **Done. NETCONF** (RFC 6241/6242, `internal/netconf`) on the same SSH server,
   subsystem `netconf`: base 1.0 and 1.1 (chunked framing), `:candidate`,
   `:confirmed-commit:1.1` (without `persist`), `:validate:1.1`,
   `:rollback-on-error`, `get-schema` and the schema list of
   `ietf-netconf-monitoring`; `get-config`/`get` with subtree filters,
   `edit-config` with every operation and `yang:insert`, `copy-config` to the
   candidate, `lock`/`unlock` (`Store.Lock`, which the CLI respects). Tried with
   ncclient.
3. **Done. State in YANG** (`yang/portitor-state.yang`, `web/state.go`): `config
   false` nodes, `system` at the top and `state` in each instance, filled from
   the API's live views as the user asks for them (so filtered per tenant and merged
   over the firewalls): interfaces and counters, routes, WireGuard, services, DHCP
   client and server leases, IP and LLDP neighbours, rule and rate-limit counters,
   BGP, OSPF, IS-IS, VRRP, BFD, NTP, NAT64, OpenVPN, and the agent, host and HA. Leaves are named after the agent API's fields, so
   `datastore.Fill` fills them without code per leaf. `info from state` in the CLI,
   NETCONF `get`. A protocol's view is asked for only when the running
   configuration has it. Not yet: routing tables beyond the main one, the BGP and
   OSPF route tables, logs, and gNMI subscriptions.
4. **The API and GUI on the tree:** a RESTCONF-like JSON API over the datastore,
   `CrudPage` fed with the schema (YANG descriptions as help, an extension for UI
   hints such as tags or transfer lists), the custom pages (rules, object tree, zone
   records, directory) kept. Then the tables go: the tree is stored as JSON per commit
   (`commits/<n>.json`, which replaces the Revert snapshots), the builder reads the
   tree, and the hand-written reference code (`objects.go`, `ifzones.go`,
   `services.go`, rename and delete checks) is replaced by the datastore's leafrefs.
   The HA replica copies the commits instead of the database.
5. **Done. SNMP**, read-only: the state of phase 3 through AgentX, a MIB generated from the
   modules. `internal/snmp/agentx` is the subagent side of AgentX (our own, small:
   open, register, get, getnext, getbulk, sets refused), `internal/snmp/mib` maps the
   state onto OIDs (lists as tables indexed by their keys and their parents', the top
   container's leaves as scalars, YANG types onto SNMP's) with the numbers kept in
   `oids.json` so they never move, and writes PORTITOR-MIB (clean with smilint, read
   by snmptranslate). portitor-config is the subagent of the host's snmpd, which the
   agent configures as the master; it answers from a snapshot of the state, refreshed
   behind the answers. Tried against net-snmp's snmpd with snmpwalk, snmpbulkwalk and
   snmpget (`PORTITOR_SNMPD_TEST=1`). The base OID is configurable: net-snmp's playpen
   until Portitor has a Private Enterprise Number. Not done: notifications, and a
   virtual firewall's own snmpd (it would need a socket per instance).

## Phase 4: the cut-over

One cut-over, on the branch `model-driven-cutover`, merged when it works; the GUI is
broken on the branch until then. The steps, in order:

| Step | What | State |
|---|---|---|
| A | **Store:** the candidate is always kept (`candidate.json`, the shared working configuration, as the database is today); commits are `commits/<n>.json`; running is the live commit's; Revert sets the candidate to running. The builder reads a tree (rows made from it by the `px:` mapping, decoded into the models it takes). Deploy, changes, preview and Revert from the tree. An old database's tables are read into the tree once, at the first start, and dropped. | Done but the dropping: the tables stay, kept in step with the candidate both ways (`syncTables`, `Store.OnChange`), for the code that still reads them until step C. |
| B | **Roles by instance name:** `roles` and `role_instances` name their instance (the only tables left that point into the configuration); access and tenancy by name. | Done. A virtual firewall's role is made when the candidate gets the instance, follows a rename (the tree records its renames, `Tree.Renamed`, for `Store.OnChange`), and goes with its grants at the commit that leaves the instance out of running and the candidate (`dropInstanceRoles`). `access` keeps a name → row id map for the handlers that take ids until step C. |
| C | **API:** `GET /api/schema` (the compiled schema for the GUI); `/api/config/...` (RESTCONF-like: RFC 7951 JSON at a path, of the candidate, running or state; PUT, PATCH, POST, DELETE on the candidate; rename and move); validation hooks per schema path (the `prepare*` checks), run when the GUI saves and at commit; actions for what is generated (WireGuard keys and client configs, certificates, OpenVPN keys, imports, bundles). The CRUD resources and their reference code go. | In sub-steps: **C1** `GET /api/schema` (`schema.Export`) and **C2** `/api/config` (`web/configapi.go`: RFC 8040 paths, `Tree.EditJSON`, access checked on every changed path of the diff; `/api/config/changes`, `/api/config/discard`) done; **C4** done: ids for new entries (`assignID`), actions by path (`web/configactions.go`; a view or operation of the CRUD's time is its handler given the entry's row id, `delegate`; generate, schedule, records, rekey on the tree or as legacy). **C3** done: formats (`yang/portitor-types.yang`, `internal/schema/formats.go`: a value checked and kept canonical by its typedef, keys too), hooks per list (`internal/confcheck`: normalize on every edit, check at every commit and on an API save; what fwconfig.Validate checks is left to it, a save's warnings), the tenancy diff check (`tenantTreeCheck`) and a new VF's seed; **C4** actions, **C5** the CRUD, the bridge and the tables go, the tests move to `/api/config`. |
| D | **GUI:** the API client and a schema store; `CrudPage` driven by a YANG list path (fields, types, enumerations, defaults and help from the schema, per-page overrides for layout); every view on it, by keys and names instead of ids. | In two parts. **D1** done: the GUI saves again, each CRUD write of a configuration row made through the tree (`throughTree`: the CRUD's handler in a transaction on the tables, read into a tree, rolled back, checked by `checkEdit` and made the candidate), its routes from before the tree back (writes with `legacyWrite`/`dbOf`); warnings toasted. **D2** done for the writes: every page writes configuration through `/api/config` (`api/config.js`: `treeApi`/`vfApi` for lists, with snake-case rows, `''` as unset, secrets marked by an RFC 7952 annotation and written as `new_*`/`clear_*`, reorders as moves, `?shallow` lists merged on update; `vfPath`/`toEntry` for the instance-level forms, each one change of the VF with its interfaces and prefixes merged in; `certificatesOf`, `dnsUpdates`, `vfWithGlobals`). Entries are named, not numbered: routes to a zone or dynamic zone go by name. New on the server for it: change actions checked by `checkEdit`, `move-to` (an interface to another VF), the certificates' `chain` view (on an entry or the whole list), a PUT of a whole list numbering entries without an id, record checks in confcheck. Left: Settings (the GUI's certificate is no configuration leaf) and the legacy routes (WireGuard and nftables import, bundles, restore, firewalls) write the tables with `syncAfter`/`legacyWrite`; reads that need row ids (the VF store, useInstanceRefs, the IPAM tree, BFD's overview, the DHCP page's interfaces) still use the CRUD's GETs, which read the tables the candidate writes. The CRUD's write routes and `throughTree` stay until `iso/portitor-setup.py` and `dev/seed.sh` are on the tree (E). |
| C5 | **The tables become a derived cache** (decided 2026-11-08): written only from the tree (`Store.OnChange`, one way); the CRUD's writes, the table→tree sync (`syncTables`, `syncFromTables`) and every other write of the tables (bootstrap, promotion, imports, bundles, a firewall's default VF) go to the tree instead; the tests move to `/api/config`. The handlers that read the tables keep doing so, and move to the tree one by one afterwards, when the tables and the configuration's migrations go. | Done but the follow-up: the configuration resources of the CRUD are read-only (`registerRead`), and the routes an action replaced are gone; the per-request sync is `syncAfter` on the routes of the handlers that still write the tables (firewalls, Settings, the imports, bundles, restore), and `ensureDefaultInstance` and the NIC import sync themselves. The tests set up through `/api/config`. An API save may add no problem (the schema's, the hooks', `firewallProblems`, the build's); what was already wrong is a warning. |
| E | **The rest:** HA replica (copies the commits and the candidate), promotion, bootstrap and join, the NIC import, backup and restore, bundles, the IP list tasks, the dashboard. | Done. The replica reads the copied tables into its candidate and fetches the live commit's configuration (`GET /ha/v1/commits/<n>`); promotion reads the tables in before it commits. `iso/portitor-setup.py`, `dev/seed.sh` and the console's `set` write through `/api/config`. Code of the CRUD's time that writes configuration into the tables runs as one change of the candidate: `viaTables` (bootstrap, a new NIC's import) or `legacyWrite` (the WireGuard, nftables and bundle imports), each in a transaction rolled back, read into the candidate, normalized and checked. The CRUD's configuration resources only answer reads (`registerRead`); their writes, `registerTree` and the bulk record, reorder and rekey routes are gone. A new IP list's task comes from its `schedule` action. Backup and restore stay as they were: a restore keeps this installation's deployments, so running stays its live commit, and the backup's configuration becomes the candidate. Left on the tables: Settings and the firewalls, which also write rows that are not configuration (`syncAfter`), and the reads that need row ids. |
| F | **Tests and docs.** | Docs: AGENTS.md (the tree as the configuration, `/api/config`, `checkEdit`, secrets, access by path, adding a feature) and the portitor-web guide (`set`, the API by path). Tests: the web tests are on the tree (`treetest_test.go` helpers), with the API's behaviour the GUI relies on (secret annotation, `""`, `null`, merges, shallow, defaults, list PUTs, `move-to`, `chain`, record checks, the console's `set`, the replica's commit). The frontend has no test runner: its pages are checked by hand (lint and build only). After the cut-over (decided): the configuration tables stay, as a read model of the tree, written only from the candidate (`Store.OnChange`); code that reads them moves to the tree when it is touched, and the tables are not dropped. Done since: the routes by row id that the entries' actions replaced are gone (two actions' access tightened to the routes': bundle export global admins only, IP list refresh a write), the CRUD's dead write code is gone (~110 functions), and the GUI's table exports are reads alone. Phase 5, SNMP, done since. |

| G | **The tables go** (decided 2026-11-09): the configuration tables, the read model, are dropped (migration 94); SQLite keeps what is not configuration. | Done. Entries' ids are kept by path in `config_ids` (`sqlmap.AssignIDs`, on every change of the candidate: kept across a rename, never another entry's, given back to an entry made again at a deleted one's path). `confview` is the candidate as rows (the models, with those ids), cached per candidate generation (`Store.CandidateGen`): the builder, the handlers that took rows and the GUI's 13 remaining reads of rows (`configreads.go`) read it. Writes are tree edits: firewalls (their host, rename and delete), Settings (`last_commit` and `web_certificate_id` stay in `settings`), bootstrap, NICs, the WireGuard and nftables imports (models added as rows, `rowWriter`/`sqlmap.Adder`), promotion (`Store.EditRaw`), bundles (format 2: the tree's JSON). A backup and the replica's copy carry the candidate and `ids.json` in the copy's table `config_snapshot`. `Import`, `Write`, the CRUD's reference code and the configuration's goose history in tests are gone. Not done: a migration of the tree's JSON for a renamed or removed leaf (a new leaf needs none). |

## How phase 1 works

(As built in phase 1, with the tables; they are gone since step G.)

**The tables stay the store**, so everything that reads them (the builder, deploy,
Revert, the HA replica, bundles, the GUI) works unchanged. The YANG modules map onto
them with extensions that go with the tables: `px:table` (a list's rows),
`px:parent-column`, `px:position` (an ordered-by user list's order), `px:column` (a
leaf that is a row id of the entry a leafref names), `px:external` (a row id of a table
that is not configuration: firewalls, roles), `px:null-value` (`main` for the main table's VRF id NULL),
`px:nullable`, `px:json` and `px:json-map` (a nested list in a JSON column).
`TestEveryColumnMapped` fails when a table or column has no YANG mapping.

Not configuration, and so not in the tree: users, roles and their members, the
firewalls (hosts, agents, HA secrets), the directory servers and mappings,
deployments, known NICs, `settings.last_commit` and `settings.web_certificate_id`.

**Row ids are kept**: an entry at the same path keeps its row. A list without a natural
key (rules, NAT rules, routes, policy routes, DNS records, syslog servers) is keyed by
its row id, so a rule keeps the id its connections are marked with. A renamed entry
keeps its row, and so do the entries below it and those whose keys named it
(`Tree.Renamed`).

**The candidate** is the tables' configuration with the CLI's edits, kept in
`candidate.json` and `candidate-base.json` next to the database (0600: they hold
secrets). When the tables change under it (a GUI edit, a commit), the edits are made
again on the new configuration (a rebase: `Diff(base, candidate)` applied to the
current tree, the candidate winning where both changed a leaf).

**A commit** checks the candidate against the schema (types, mandatory leaves,
leafrefs), writes it into the tables (`sqlmap.Write`, in a transaction, foreign keys
deferred) and runs the GUI's `deploy`. When the deploy fails, the tables get back what
they held and the candidate keeps its edits. **Running** is the live commit's Revert
snapshot, read with the same bridge.

**Checks:** the schema's (types, enumerations, mandatory leaves, leafrefs; a union
with a plain string member, as the address and interface lists have, accepts any
name) and then the builder's and `fwconfig.Validate`'s at the deploy. The GUI's entry
checks in `web/resources.go` don't run for the CLI's edits; the builder and the agent
still refuse what can't be deployed. Moving those checks to the datastore (validation
hooks per path) is part of phase 4.

**Access**, by path: global admins everything, global viewers read; others read the
virtual firewalls of their roles and the shared objects, and change those they are
admins of (not `firewall` or `is-default`), and their commits deploy only those. An HA
secondary's CLI is read-only.

## Known gaps

- References a leafref can't express are not rewritten by a rename: link ends in
  interface lists, `@iplist` in address lists, an IP list in a task by name. The
  builder reports what doesn't resolve.
- The CLI has no `request` commands yet for what the GUI generates (WireGuard keys,
  certificates, OpenVPN keys); the GUI does those.
- The SSH port isn't in the anti-lockout rule; an input rule opens it.
- NETCONF: no `:writable-running`, `:startup`, `:url`, `:xpath`, `persist` or
  `kill-session`.
  NETCONF runs on `ssh_listen`'s port, not 830.
