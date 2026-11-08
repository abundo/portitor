<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Design: a model-driven configuration

Status: phases 1 to 3 implemented, 2026-11-08. There are no production systems, so no
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
| SQL bridge | `internal/datastore/sqlmap` | reads the tree from the tables and writes it back, keeping row ids |
| NETCONF | `internal/netconf` | the NETCONF server on the datastore: framing, XML, edit-config, subtree filters, commit, locks, get-schema |
| CLI | `internal/cli` | the command line, its help and completion from the schema; the terminal, scripts and the SSH server |
| State | `yang/portitor-state.yang`, `web/state.go` | the live data as `config false` YANG, from the API's live views |
| Backend | `web/datastore.go` | Current (the tables), Running (the live commit's snapshot), Commit (write and deploy); access by role; SSH logins |

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
   false` nodes, `system-state` at the top and `state` in each instance, filled from
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
5. **SNMP**, read-only: the state of phase 3 through AgentX, a MIB generated from the
   modules.

## How phase 1 works

**The tables stay the store**, so everything that reads them (the builder, deploy,
Revert, the HA replica, bundles, the GUI) works unchanged. The YANG modules map onto
them with extensions that go with the tables: `px:table` (a list's rows),
`px:parent-column`, `px:position` (an ordered-by user list's order), `px:column` (a
leaf that is a row id of the entry a leafref names), `px:external` (a row id of a table
that is not configuration: firewalls, roles), `px:global-ref` (a DNS template of the
instance, or a global one), `px:null-value` (`main` for the main table's VRF id NULL),
`px:nullable`, `px:json` and `px:json-map` (a nested list in a JSON column).
`TestEveryColumnMapped` fails when a table or column has no YANG mapping.

Not configuration, and so not in the tree: users, roles and their members, the
firewalls (hosts, agents, HA secrets), the directory servers and mappings,
deployments, known NICs, `settings.last_commit` and `settings.web_certificate_id`.

**Row ids are kept**: an entry at the same path keeps its row. A list without a natural
key (rules, NAT rules, routes, policy routes, DNS records, syslog servers) is keyed by
its row id, so a rule keeps the id its connections are marked with. A rename of an
entry keyed by name is a new row; rows that referred to it by id follow it, but a
virtual firewall's role is made again (its members are lost).

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
- Renaming a virtual firewall in the CLI loses its role's members.
- The CLI has no `request` commands yet for what the GUI generates (WireGuard keys,
  certificates, OpenVPN keys); the GUI does those.
- The SSH port isn't in the anti-lockout rule; an input rule opens it.
- NETCONF: no `:writable-running`, `:startup`, `:url`, `:xpath`, `persist` or
  `kill-session`.
  NETCONF runs on `ssh_listen`'s port, not 830.
