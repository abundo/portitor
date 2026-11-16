<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Design: no database

Status: decisions D1, D2, D8, D9 and the scoped commit made 2026-11-14. Phase 0 done 2026-11-15 (`internal/records`), but for the generic CRUD (firewalls, the directory's servers and mappings) and the database file's operations, which keep `Server.db` until phases 3 and 5. Phases 1 and 4 done 2026-11-15. Phase 2 done 2026-11-15 (see "Global lists and the scoped commit": the users, roles and directory are global lists; `treeRecords`); Phase 3 done 2026-11-15 (firewalls are a global list too). Phase 5 done in two releases: stage A in 1.0.0 (2026-11-16), stage B (no database) for 1.1.0, built 2026-11-16. Builds on `design-model-driven.md`
(the configuration is the tree; the tables are gone since 0.9.0).

## Goal

Remove SQLite. Everything portitor-config keeps lives in the YANG tree, so **a
backup is the configuration**: one document, restorable on a new host, copied
to an HA replica, diffed, versioned and edited with the same tools as the
rest (GUI, CLI, NETCONF, API).

Not goals: changing the document the agent gets (`fwconfig`), the agent, or
`render`; a second storage engine.

## What the database holds today

After migration 94 (0.9.0) the configuration is out of SQLite. What is left
(`models.Stored()` and `config_snapshot`):

| Table | What | Kind |
|---|---|---|
| `users` | name, profile, password hash, directory server, role, TOTP secret/pending/required, recovery code hashes | configuration + secrets, plus runtime (`token_version`, `totp_last_step`) |
| `roles`, `role_members`, `role_instances` | roles, their members and instance grants (by name) | configuration |
| `ldap_servers`, `ldap_role_mappings` | the directory | configuration + secrets (bind password) |
| `firewalls` | name, agent URL/token/fingerprint, HA pair (primary, secret, epoch, witness, config URL/fingerprint) | configuration + secrets, plus runtime (`generation`, `ha_epoch`) |
| `deployments` | one row per apply: commit, firewall, generation, user, status, message, log, redacted document, hash | history, not configuration |
| `known_interfaces` | NICs the agent has seen, per firewall | discovered state |
| `config_ids` | entry id by path | bookkeeping of the tree |
| `settings` | `last_commit`, `web_certificate_id` | counter + a reference |
| `config_snapshot` | the candidate and ids in a backup and in the replica's copy | transport |

Code that touches it: `Firewall` in 18 files, `User` in 11, `Deployment` in 5,
roles and directory in 3 each; about 40 `s.db` call sites in `web/`
(`handlers.go`, `commit.go`, `auth.go`, `firewalls.go`, `roles.go`, `totp.go`,
`replica.go`, `directory.go`). Also: backup/restore (`backup.go`,
`snapshot.go`), the replica's database copy (`replica.go`), `portitor-config
migrate`, `install.py`'s database moves, the dev and ISO scripts.

## Principle: three kinds of data, three homes

Putting "everything" in the tree does not mean putting everything in the
candidate. The columns above are of three kinds:

1. **Configuration** (users, roles, directory, firewalls, their secrets): YANG
   lists in the tree. This is what the backup holds.
2. **Runtime state that must survive a restart** (`token_version`,
   `totp_last_step`, `generation`, `ha_epoch`, the commit counter, login
   limits that persist): a small `state.json` next to the tree, written
   atomically, owned by portitor-config. Never in a commit, a diff or the
   candidate; not in the backup (a restore starts sessions anew and takes the
   generation from the agents, see below).
3. **History** (deployments, known NICs): files, not tree. Deployments as an
   append-only log (`deployed/`, which already holds each commit's
   configuration and each firewall's document); known NICs rebuilt from the
   agent's status, with no storage (they are only "seen before" hints).

The tree stays the one place a human edits configuration; `state.json` and the
log are the server's.

## Decisions

Decided (maintainer, 2026-11-14):

- **Everything configuration goes in the tree; a backup is the configuration.**
- **D1. Runtime state in `state.json`**, not in the tree: `token_version`,
  `totp_last_step`, `generation`, `ha_epoch`, the commit counter, persistent
  login limits. Written atomically, owned by portitor-config, never in a commit,
  a diff or the candidate, and not in the backup.
- **D2. Users, roles and the directory are part of the candidate/running
  split**, like the rest. A user change is a candidate edit; a change of a
  password (or a user's own profile) is a candidate edit followed by a direct,
  *scoped* commit (D2a), so it takes effect at once without committing
  anyone else's pending changes.
- **D8. Roles are their own list, with their members** (see Phase 2).
- **D9. Deployment history retention is configurable** (see Phase 4).

Resulting design points:

- **D2a. Scoped commit.** The candidate is shared, so a direct commit of "the
  whole candidate" would publish other people's half-made edits. A scoped
  commit takes a set of paths from the candidate into running and leaves the
  rest of the candidate as it is (the other users' changes stay pending).
  Instance admins' commits already work this way (`deploy`'s `only`,
  `mergeRunning`, `tenantTreeCheck`); this generalises that to paths, with
  the same checks (`checkEdit`, access by path). A conflict (the same path
  changed in the candidate by someone else) refuses, as a rebase does now
  (`Store`'s rebase).
- **D2b. A user change may still reach the agents.** The document carries the
  OpenVPN users' hashes, TOTP secrets and the directory (`Document.Directory`).
  A scoped commit of a user runs the normal `deploy` (all changed documents,
  confirm window per the settings); a firewall without OpenVPN builds the same
  document, so nothing is applied there (`commitTargets`: unchanged hash).
  Changing your own password therefore never waits for a confirmation on a
  firewall that does not use it; on one that does, it applies like any commit.
- **D2c. Lockout.** Running always holds a working admin: a candidate that
  has none is refused (a check, as now for the last global admin), and
  Revert/Discard only ever go back to running. Anything beyond that is
  `portitor-config createadmin`, which edits the files directly and commits.
- **D3. Backup = running configuration + users + roles + directory +
  firewalls** (all in the tree), age-encrypted with a passphrase as today.
  Not the deployment log, not `state.json`. Restore writes the tree and
  starts with fresh sessions; generations are re-learned (D4).
- **D4. Firewall `generation`** is the last number handed to an agent, so
  agents never see one twice. After a restore it is unknown: take
  `max(state.json, agent's reported generation) + 1` from `GET /v1/status`
  before the next apply. The agent already reports it.
- **D5. IDs.** `config_ids` becomes `entry-ids.json` beside the candidate (not
  `ids.json`, which holds the high-water marks of the lists keyed by a number). Ids are the rules' `ct
  mark`s and instances' HA addresses, so they are written in the same
  transaction as the commit file. They go in the backup.
- **D6. The commit counter** is the highest of `state.json`, the deployment log
  and `deployed/<n>-config.json` (a failed apply still takes a number).
- **D7. Concurrency.** One process owns the files (as it owns the database
  now), with an in-process lock per file and `rename` for every write; the
  HA replica reads the primary's files over the existing authenticated
  endpoint, never the files directly.

## Phases

Each phase ships, tests pass, and SQLite shrinks.

**Phase 0: the seam (no behaviour change).** A package `internal/records`
(not "state": that word is the YANG state, `state.json` and the operational
tree) with an interface in front of everything the database holds, and every
`s.db` call site in `web/`, the builder and `confview` moved behind it,
implemented on GORM. Shaped after the three homes, so each later phase swaps
one implementation:

- *Directory data* (users, roles and their members and grants, the LDAP
  servers and mappings, firewalls): reads and coarse writes. Phase 2 and 3
  replace the admin CRUD with `/api/config`, so these stay small.
- *Runtime* (token version, TOTP step and pending, recovery codes, generation,
  HA epoch, the commit counter): its own methods, never carried by a save of a
  whole row. The TOTP "each code once" and recovery-code uses are single
  conditional operations (compare-and-set), not read then write.
- *History* (deployments, known NICs): append and query.

Rules for the signatures: domain operations only, no `*gorm.DB`, column names,
order strings or `map[string]any`; a method must be implementable by the tree
plus a JSON file. Operations that are one transaction today (a promotion, a
role's save with its members and grants, a directory login that creates a
user and syncs roles, the instance-role rename) stay one method. The generic
CRUD `resource[T]` keeps GORM as the one recorded exception until its
resources move to the tree. Outside the seam, in phase 5: backup, restore,
the replica's file copy, `migrate`. The builder declares the narrow read
interface it needs; `builder.Input` carries it instead of `*gorm.DB`. Contract
tests run against the GORM implementation and become the acceptance tests of
phases 1 to 4. *Size: the largest single step, mostly mechanical.*

**Phase 1: ids, counter, settings.** `ids.json` and `state.json` replace
`config_ids` and `settings`; the web certificate id becomes the tree's
reference (by name, as the GUI already names certificates).

**Phase 2: users, roles, directory.** Top-level YANG lists, in the candidate:

- `user` (key `name`): `full-name`, `email`, `date-format`, `role`
  (`admin`/`viewer`/`none`, the global role), `ldap-server` (leafref),
  `totp-required`; secrets as `px:secret`: `password-hash`, `totp-secret`,
  `recovery-code-hashes`. `totp-pending` is a setup in progress, so runtime
  (`state.json`), as are `token-version` and `totp-last-step` (D1).
- `role` (key `name`): `instance` (the VF a per-instance role belongs to, as
  `roles.instance` now; leafref), `member` (leaf-list, leafref to `user`) and
  `grant` (list keyed by `instance`, leafref, with `level` admin/viewer).
  A rename of a user or an instance rewrites these by the leafrefs;
  `syncInstanceRoles`, `renameInstanceRoles` and `dropInstanceRoles` become
  tree edits in the same commit (the roles of an instance made when the
  candidate gets it, removed when a commit leaves it out, as now).
- `ldap-server` (key `name`, ordered) and `ldap-role-mapping`
  (`group-dn` -> `role` leafref), the bind password a `px:secret`.

Access by path (`treeAccess`): users, roles and the directory are read and
written by global admins only; a user's own profile and password are actions
(`change-password`, `update-profile`, TOTP setup/enable/disable) that edit
the user's own entry and commit it scoped (D2a), checked against the caller.
`authenticateUser`, sessions, TOTP and OpenVPN's login data read the tree
(running, not the candidate: a login follows what is committed).

**Phase 3: firewalls.** YANG list `firewall`; the agent token and the pair's
secrets as `px:secret`; `generation` and `ha_epoch` to `state.json`.
`firewalls.go` and the HA code (`promote`, `witness`, `replica`) read the
tree. `swapHAValues` becomes a tree edit (`Store.EditRaw`, as now).

**Phase 4: deployments.** An append-only log with an index by commit and
firewall; the history page and `latestDeployment`/`liveDeployment` read it.
Known NICs dropped (derived from the agent's status). Retention is a setting
in the tree (`deployment-history`): `keep-deployments` (a count; 0 is all) and
`keep-days` (an age; 0 is no limit), either bound pruning the oldest first;
defaults 500 and 365. The same container takes the number of commits'
configurations kept for Revert (`snapshotKeep` now), with a floor of one,
the live commit, which is never pruned, nor is the deployment that made it.
Pruning runs after a commit, as `pruneSnapshots` does.

**Phase 5: the database goes.** Remove GORM, goose, `dbmigrate`, `portitor-config
migrate` (replaced by a tree-version check that refuses an old layout), the
database moves in `install.py`, `config_snapshot`. Backup is the tree export;
the HA replica copies the tree (it already copies the live commit's
configuration).

## The upgrade

A 0.9.x installation has users and firewalls in SQLite. The release that moves
them (phase 2 and 3) reads the old database once, writes the tree and
`state.json`, and renames the database aside (`portitor.db.migrated`, kept
until removed by hand). That is a reader of the old database again, so the
rule is the one 0.9.0 set: **an installation must be on the release that
imports, once, before going further**; the release after it removes the reader
and refuses an older layout (as `dbmigrate.MinVersion` and
`install.py check_upgrade_path` do now). The import is the only place that
keeps GORM until phase 5.

## Risks

- **Secrets in one file.** The tree now holds password hashes, agent tokens,
  and the pair's secrets. The file is 0600 owned by the service user, never
  returned by the API (`px:secret`), redacted in logs, and encrypted in the
  backup; the redacted-history rule for deployments is unchanged.
- **Lockout.** The user list is in the tree: a bad restore or a corrupt file
  locks everyone out, and an edit that removes the last admin is refused
  (D2c). `portitor-config createadmin` (console, root or service user) must
  keep working with the files alone, and a failed load refuses to start
  rather than start empty. A candidate that is discarded or reverted never
  changes the users in running.
- **A scoped commit's edge cases.** The path set must close over references:
  committing a user that a pending role names, or a role whose instance is
  still only in the candidate, must refuse or take the dependency with it.
  Phase 2 settles this with the leafrefs (a scoped commit takes the paths and
  everything they reference, or refuses naming what is missing).
- **Atomicity across files.** A commit writes the configuration, ids and
  state: the order is (1) deployed config, (2) ids, (3) state, and a start
  repairs by trusting the highest complete commit file.
- **Scale.** Users and deployments are small; the log is the one that grows
  (pruned like `snapshotKeep`). No query beyond "by commit" and "by firewall"
  is needed, which an index file serves.
- **The HA replica** loses its "copy the SQLite file" simplicity: it fetches
  the tree, the users and the firewalls as one bundle with the pair's secret,
  as it fetches the commit's configuration today.

## Global lists and the scoped commit (built 2026-11-15)

The way through what phases 2 and 3 found (next section) is a set of *global
lists*, top-level lists committed apart from the deployed configuration
(`web/globals.go`, `globalLists`, empty until the users are in the tree):

- What runs of them is `global.json` next to the database, not the live
  commit's configuration. `Running` is the live commit's file with the global
  lists replaced by that file's. So a deployment waiting for confirmation, and
  its rollback later, leave them as they are: running is never rebuilt from a
  stack of numbered commits.
- A full commit also writes `global.json` from what it commits (the candidate's
  lists); the commit's own file holds them as history only.
- A *scoped commit* (`datastore.CommitOptions.Scope`, `Store.Commit`; the CLI's
  and NETCONF's commit of a path is to follow) takes the named global lists from
  the candidate into running and nothing else: the rest of the candidate stays
  pending, and the candidate and running agree on those lists afterwards. If
  that changes a firewall's document (the OpenVPN users, the syslog servers) the
  changed firewalls are deployed like any commit, the others untouched. If it
  fails to deploy (a firewall that can't be reached, a change waiting for
  confirmation) the lists stay committed and the answer is a warning; the
  documents follow at the next commit. If no document changes nothing is applied
  and no commit is numbered.
- Tested on `syslog-server` (changes the documents) and `certificate-authority`
  (doesn't): `web/globals_test.go`, including a commit that is pending when a
  scoped one is made and then rolled back.

The directory's servers (`ldap-server`) are the first global list, done end to
end: the YANG list (`yang/portitor-access.yang`, mapped onto the old table's
model), adopted once from the database with their ids and order (an earlier
release's data is a test: `TestOpensAnEarlierReleasesData`), read by logins from
running and by the builder from the tree it builds, written by `treeResource`
(the old routes, each write a scoped commit, taken back out of the candidate when
the commit is refused), hidden from viewers (`adminLists`), carried by a backup
and the replica's copy, and adopted again from a restored old backup's database.
The golden documents are unchanged.

A document is a function of its tree, so the builder should read the users, the
directory and the memberships from the tree it is given (the candidate for a full
commit, running with the scoped lists for a scoped one), not from `records`.
That is part of phase 2.

Phase 2 is therefore, in order: the YANG lists (`user`, `role`, `ldap-server`,
`ldap-role-mapping`) with `px:table` mapping onto the models, the import from the
database keeping the SQL ids (`IDs.Set`: a session cookie carries the user id), the
builder and `records` reading them from the tree (an index per live commit:
`requireAuth` runs on every request), then the write path as wrappers over tree
edits with a scoped commit, the self-service actions scoped to the leaves they
set, directory logins written to running and the candidate together, and the
token version and TOTP step (which only grow) merged by maximum to the replica.
A deleted user's token version is kept and bumped, so an old cookie never fits a
new user of the name. `treeAccess` must hide these lists from viewers, who read
everything else.

## Found before phases 2 and 3

Building phases 0, 1 and 4 showed that phase 2 and 3 can't be built as written
above. They need decisions, and AGENTS.md says to stop and ask:

- **A commit without an apply.** `deploy` applies every firewall again when no
  document changed (`targets = same`), refuses while a change waits for
  confirmation, and fails on an unreachable agent. So a user change committed
  "scoped" (D2a) would apply every firewall again, or be refused during a
  confirm window, or fail with a firewall down. A scoped commit needs a path
  that moves running (and writes the commit's files and the counter) without
  deploying when no document changes. Check `liveCommit` first: running
  advances only with a deployment row today.
- **Logins write.** A directory login creates or updates the user and syncs
  memberships, and `runDirectorySync` copies OpenVPN logins in every 30 s.
  Each would be a commit if users are tree data (D2). Needs a rule: such
  writes bypass the candidate (D2 reversed for them), or are batched.
- **Revocation must reach the replica.** Sessions are valid on both hosts of an
  HA pair (`sessionKey`), so `token_version` and the TOTP replay step must be
  copied to the standby; D1 puts them in `state.json`, which the replica does
  not copy.
- **Firewalls.** A commit needs the agent connection of the firewall it is
  changing, and `newAgent` reads the firewall rows. If firewalls are tree data,
  the agent connection used for a commit is the running one, not the candidate's,
  so a changed agent URL or token takes effect at the next commit, not at once.
  Bootstrap (`SetAgent`, first start) has no commit to ride on.
- **The web certificate** is a tree reference only if it takes effect at commit
  (not at once, as now) and deleting the certificate is refused while it is
  chosen.

The pieces that do not depend on those decisions are done: the seam
(`internal/records`), the ids and counters in files, the deployment log with
configurable retention, the known interfaces in a file (they must stay stored:
`syncNICs` imports a NIC that is neither known nor configured, so a NIC the
user removed would come back at the next poll).

## Operational state and streaming (a separate track)

Not part of removing the database, but it touches the same line between kinds of
data, so it is fixed here. Today the state tree (`portitor-state.yang`,
`web/state.go`) is pulled: each request asks the agents' live views and fills
the tree, and SNMP caches the result for 10 s. Nothing is pushed, so nothing can
be streamed.

- **Operational state is not `state.json`.** `state.json` is the server's
  persisted bookkeeping (D1): small, written atomically, kept across restarts.
  Operational state (interfaces, leases, neighbours, routing protocols, HA,
  counters) is an in-memory tree, rebuilt after a restart, never persisted and
  never in a backup or a commit.
- **Push, with change notification.** The agent publishes changes of its state
  to portitor-config (over the existing agent API, a long-poll or stream like
  the DHCP replication's), which updates the in-memory state tree and notifies
  subscribers of the subtrees that changed. The live views, SNMP's AgentX
  subagent and a later gNMI Subscribe (on change and sampled) are frontends of
  that one tree, so a state leaf defined in YANG is in all of them.
- **Alternative:** portitor-config keeps polling and diffs against the last
  answer to produce notifications. Simpler (no agent change), costlier, and
  coarse for fast-changing state. Decide when this track starts.
- **Seam.** Phase 0's state interface covers only what the database holds now;
  the operational tree is a different type with different guarantees
  (lost on restart, eventually consistent) and stays out of it.
- **Sessions.** Treating sessions as runtime (a restart ends them, a boot nonce
  replacing `token_version`, the TOTP replay record in memory) would shrink
  `state.json` further. Not proposed now: an HA pair's sessions are valid on
  both hosts by design (`sessionKey`).

## Decided later in review

- **The scoped commit is a general datastore operation** (D2a): a `commit` of a
  set of paths in the CLI and NETCONF's partial commit, not only internal to
  the self-service actions. The actions are its first user.
- **A user's profile edits** (name, email, date format) are scoped commits
  too, through the same self-service action as the password change.

## Not decided

- Retention defaults for the deployment log (D9) beyond the proposed 500 and
  365.
- Whether the operational state is pushed or polled and diffed (above).

## Phase 2 as built

- **The lists.** `user`, `role` (with `member` and `grant`), `ldap-role-mapping` and
  `ldap-server` in `yang/portitor-access.yang`; `ovpn-role` is a leafref to the
  role (a rename follows). Hidden from viewers (`adminLists`).
- **Adoption.** `adoptAccess`, once and before anything is served (in the tree's
  set-up), takes the old tables with the ids the rows had and the highest id each
  table ever gave (`sqlite_sequence`), so a deleted user's id is not given again
  and a session cookie never fits another user. A restored old backup is adopted
  again from its database. Tested against a real earlier release's data
  (`TestOpensAnEarlierReleasesData`, `HEAD_DATA`), the deleted users, token
  versions, TOTP and members included.
- **Reads** are an index of what runs (`accessIndex`), rebuilt when `global.json`
  changes; **writes** (`editAccess`) go to what runs and to the candidate
  together, under the lock the processes of one installation share. A login
  writes nothing unless a user or a membership changed; a used recovery code is
  `sessions.json`'s. Instance roles are made and renamed in both trees at once.
- **Sessions and the replica.** A changed password or role, or a removed user,
  raises the token version wherever it was written (the writer of `global.json`
  compares). `sessions.json` is in the replica's copy, merged by maximum and union.
- **Not done, on purpose:** the old SQL methods of `records` for users, roles and
  the directory are still there, unused (`treeRecords` overrides them); they and
  the old tables go with phase 5. A scoped commit never deploys for these writes
  (the documents follow at the next commit, as they did), which also holds for the
  directory's servers.
- **Behaviour that changed:** a backup holds the users, roles and directory (a
  restore brings them back, a user made since is gone, the sessions stay); a
  password change made while a commit awaits confirmation is committed at once.

## Phase 3 as built

- **The list.** `firewall` (key `name`) in `yang/portitor-access.yang`, ids and the
  highest id the table gave adopted once (`adoptFirewalls`, its own marker; the
  deployments name the firewalls by id), the generations into the runtime file
  (`sessions.json`, only raised, merged by maximum). Instances' and tasks'
  `firewall` leaves are leafrefs (a rename follows in the candidate); `ha-primary`
  is a leafref, the pair's secrets and epoch are leaves. Verified against a real
  earlier release's data with a deleted firewall (a gap in the ids), an HA
  secondary, a renamed one and a pending commit: ids, fields, secrets,
  generations, the live commit and each firewall's live deployment are as they were.
- **Reads and writes.** `treeRecords` answers `Firewalls`/`Firewall` from the index
  of `global.json`; `EnsureFirewall`, `SetAgentConnection` and `PromoteFirewalls`
  are writes to what runs and the candidate together (the promotion also on a
  replica, which is what it ends being). The builder reads the firewalls from the
  tree it builds. `/api/firewalls` is a `treeResource` with hooks (a new firewall
  gets its default instance in the same edit; a delete takes its host and tasks,
  put back if the commit is refused).
- **What the phase 2 review found, fixed first.** The candidate is re-read when
  another process changed it (`createadmin` survives the daemon's next commit);
  the global lists are read, checked and given ids without the deployed part (a
  renamed role the live commit names no longer breaks every write), and a change
  is refused only for the problems it adds; a user or role renamed in the
  candidate alone is refused (it would get two ids); `Store.Commit` runs its
  backend without the store's lock, so what a commit does afterwards (dropping
  the roles of a deleted virtual firewall) can edit the candidate.
- **Behaviour that changed:** a firewall made or changed is not refused for what
  the documents lack of it (an HA pair needs its links, added after); a backup
  keeps this installation's firewalls (as before) and its ids.

## Phase 5, stage A as built (the adopting release)

Phase 5 needs two releases: this one adopts what the database holds and still
depends on SQLite to read it once; the next has no database at all (stage B:
GORM's sessions, goose, `dbmigrate`, `migrate`, the old tables, the adoptions and
the old readers are removed) and refuses a data directory without `layout.json`,
telling the user to update through this release first. 1.0.0 was released from
stage A; stage B followed on `main` (below).

Stage A: everything but the adoption is independent of the database.

- **A copy is an archive** (`web/copybundle.go`), for a backup (age-encrypted) and
  the replica (`GET /ha/v2/bundle`, the ETag the archive's hash): a manifest with
  the format first, an allow-list of names, only plain files, read into memory
  (never extracted to a path the archive names), a size limit, sorted names and no
  times. A restore stages through `takeSnapshot`.
- **Old formats.** A secondary updated before its primary still takes the database
  file (`/ha/v1/database`, `takeLegacyCopy`: adopted into the tree); an earlier
  release's backup is refused ("restore it with that release, then update"): its
  users table is stale after the adoptions, and a backup restored over a fresh
  installation would otherwise replace the users with nothing. A pair is updated
  secondary first, together (`docs/ha.md`).
- **One data directory** (`Config.Dir()`, next to `db.path`, which existing
  `config.yaml` files have); the commits' directory no longer asks SQLite.
- **`Ready()`** makes every file (from the old tables where there is none) and
  writes `layout.json`, so stage B has nothing to seed.
- **What a review of stage A found, fixed:** a full commit used to write the global
  lists of the tree it prepared (a password changed meanwhile was put back); it
  takes the candidate as it is then. A firewall renamed in the candidate alone is
  refused, as a user is, and a refused commit of a renamed entry puts its id back.
- **Not done:** the last-firewall and pair rules are still handler-only (not
  `confcheck`'s, so `/api/config` and the CLI skip them); `make iso-e2e-update`,
  the real upgrade test, has not been run.

## Phase 5, stage B as built (no database, 1.1.0)

- **Gone:** `internal/dbmigrate` (goose, the SQL migrations, `MinVersion`), GORM's
  `records` implementation and its seeding from the old tables, the adoptions
  (`adoptAccess`, `adoptFirewalls`, `adoptions.json` no longer written), the
  replica's database copy (`/ha/v1/database`, `takeLegacyCopy`), `restoreDatabase`
  and the `config_snapshot` reader, the generic CRUD `resource[T]` (`crud.go`; its
  error helpers are `errors.go`), `Server.db`, `ConnectDB`, `models.Stored`,
  `KnownInterface` and `User.AfterFind`, `px:external` (in sqlmap and the
  extensions module: nothing named a row outside the tree any more), and the
  database moves in `install.py` (`move_web_database`, `move_remote_database`,
  `old_web_database`, `link_*_config`).
- **records.** `Files` (`store.go`, `NewFiles(dir)`) implements `Kept`: history,
  counters, ids, sessions and generations. `web`'s `treeRecords` embeds it and
  answers the users, roles, directory and firewalls from the tree, so `Store` as a
  whole is only ever `treeRecords`. A copy without `entry-ids.json` is refused.
- **confview** reads the models' columns itself (`fields.go`: embedded structs,
  `gorm:"column:"`, `gorm:"-"`, `gorm:"default:"`, relations skipped, gorm's
  snake-case naming with its initialisms), the tables from one list
  (`viewTables`, `tableOf`) instead of gorm's pluralising. Checked, before gorm left
  the module, against gorm's parser for every model (tables, columns, defaults,
  `RowOf`) and its decoder on seeded rows: the same.
- **The start gate** (`checkLayout`, in `core`): no data directory is memory (tests);
  `layout.json` at `layoutVersion` opens; a higher one is refused ("a later
  release"); a lower one, or none with `candidate.json`, `global.json`,
  `entry-ids.json`, `deployed/` or the database file there, is refused ("update to
  Portitor 1.0.0 and start it once"); an empty or missing directory is a new
  installation and gets its `layout.json` at once. A `portitor.db` beside a 1.0.0
  directory is never read or removed. The root guard is `CheckDataDir`.
- **The first firewall** came from migration 63; `Ready()` makes it now
  (`ensureFirewall`), since `install.py` runs `set-agent` right after `migrate`.
- **`portitor-config migrate`** stays, as the layout check: 1.0.0's `install.py`
  (the agent's copy, which runs a GUI update) calls it on the new binary.
- **install.py** refuses an installation older than 1.0.0 (`MIN_UPGRADE_FROM`) and,
  for every firewall, a data directory with the old files and no `layout.json`
  (`check_data_dirs`, as root), before anything is replaced, for releases,
  `--source` and `--local`.
- **Found on the way, fixed:** a restore set the ids' high-water marks back to the
  backup's (`entry-ids.json` and `ids.json`), so an entry or rule made after the
  backup could have its id given again (a rule's id is its connections' mark); the
  test that should have caught it read `sqlite_sequence`, which nothing wrote since
  0.9.0. The copy's marks are now raised to this installation's (`IDs.KeepHigher`).
  A copy without `global.json` is refused before the candidate is replaced.
- **Acceptance:** `web/testdata/release-1.0.0` is a data directory written by 1.0.0
  (two firewalls, a directory server, a commit and a pending change, no database);
  `TestOpensA100DataDirectory` opens it and builds the documents 1.0.0 built,
  `TestLayoutGate` the refusals.
- **Still there:** `gorm.io/gorm` and SQLite in `go.mod`, indirect, for dnsmgr2's
  `dnsmgr` package, which `internal/render` imports for its config types (dnsmgr2
  has a database of its own); both binaries link them. Removing them is a change in
  dnsmgr2 (its types apart from its storage). The models keep their `gorm:` tags as
  plain column names. `make iso-e2e-update` from 1.0.0 has not been run. The e2e
  update scripts start from 1.0.0 or later (their branches for a release before
  portitor-config are gone) and check `layout.json` after the update.
