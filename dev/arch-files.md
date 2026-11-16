<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# The data directory: files, locks, numbers, recovery

What portitor-config keeps on disk since 1.1.0 (no database), and the rules code
that touches it must keep. Why it is built this way is in
[design-no-database.md](design-no-database.md). This file says what holds now. Keep
it up to date with the code, as AGENTS.md is.

## Ownership

The data directory is `Config.Dir()` (the directory of `db.path`). It belongs to the
service user `portitor`, and only portitor-config writes it: the daemon, and the
console commands run beside it (`portitor-config set/commit/cli/createadmin/...`,
as root or the service user). As root it refuses a directory owned by another user
(`CheckDataDir`). The agent never reads it. It gets documents over its API and keeps
its own state under its `state_dir`.

| File | What | Writer | In a backup / the replica's copy |
|---|---|---|---|
| `layout.json` | the layout version (`layoutVersion`, 3) | `checkLayout` | no |
| `candidate.json` | the candidate tree, with secrets | `datastore.Store` | yes |
| `global.json` | what runs of the global lists (users, roles, directory, firewalls, ...) | `web/globals.go` | yes |
| `deployed/<n>-config.json` | the tree commit `n` deployed; the newest `snapshotKeep` kept | `saveCommit` | no; the replica fetches the live one (`GET /ha/v1/commits/<n>`) |
| `deployed/<n>-<fw id>.json` | the document a firewall got at commit `n` | `keepDocument` | no |
| `ids.json` | the numeric list ids given (`nextID`) | `web/configapi.go` | yes, never lowering ours |
| `entry-ids.json` | the entries' ids, by path | `records` (`FollowChange`) | yes, never lowering ours |
| `state.json` | the commit counter, the web certificate | `records` | no |
| `deployments.jsonl` | the deployment log | `records` | replica only |
| `sessions.json` | users' runtime values, firewalls' generations | `records` | replica only |
| `known-nics.json` | NICs seen per firewall | `records` | replica only |

`records` (`internal/records`) owns every file in that list that isn't configuration.
A new kind of runtime state goes there, as a field or a file, with its place in
`copyFiles`/`ExportState`, never in the tree.

## Locking

Two processes can share a directory: the daemon and a console command. Each shared
area has an in-process mutex and an `flock` on a lock file (`datastore.LockDir`).
The flock is held from read to write. A lock that can't be taken fails the
operation; nothing goes on without it.

| Lock file | Guards | Taken by |
|---|---|---|
| `.candidate.lock` | `candidate.json` | every `Store` edit, commit, discard (`Store.lockFile`, under `Store.mu`) |
| `.records.lock` | the `records` files | `fileState.beginWrite` (under `fileState.mu`) |
| `.globals.lock` | `global.json` | `Server.lockData`; not re-entrant |

Order: an edit takes the candidate lock, then `Store.OnChange` → `FollowChange`
takes the records lock. Never take the candidate lock while holding the records lock.

Changes made by the other process are picked up by stamp (size and mtime,
`datastore.StampOf`). Before using its copy, each holder checks the file's stamp and
reads the file again if it changed (`Store.candidate`, `fileState.refresh`). Reads
of `records` take only the mutex. They see either the old file or the new one,
never a mix, because files are replaced whole (below).

On top of that, `deployMu` allows one commit at a time per process, and the agent
refuses a second pending change. NETCONF/CLI datastore locks (`Store.Lock`) are
per session, in memory, not files.

## Writes and crash recovery

- **Whole files** go through `datastore.WriteFile`: written to `<file>.tmp`, then
  renamed over the file. If the process crashes, the file is the old one or the
  new one. There is **no fsync** of the file or the directory, so a power loss
  can lose the last write (or, depending on the filesystem, leave it empty). Only
  the deployment log syncs. Known gap; fix it in `WriteFile` if it matters.
- **The deployment log** is append-only JSON lines, each appended and fsynced
  (`appendDeployment`). A line cut short by a crash is skipped on read
  (`parseDeployments`). The log is compacted by rewriting it whole.
- **Edit order.** `Store.set` runs `OnChange` (entry ids into `entry-ids.json`)
  before writing `candidate.json`. A crash between the two leaves ids for entries
  the candidate doesn't have. That is harmless: ids are by path and never reused.
- **Commit order** (`deploy`): `saveCommit` writes `deployed/<n>-config.json`;
  `reserveNumbers` writes the counter and generations; then the agents apply; then
  `recordDeployments` appends the log and keeps each document. **Running is
  whatever the deployment log says** (`liveCommit`: the highest `commit_id` among
  the firewalls' live deployments), not `state.json`. So a crash before the log
  line leaves the earlier commit running in portitor-config's view, even if an
  agent applied the new one. The next commit or the agent's own rollback (if it
  was a confirmed commit and is never confirmed) brings the two together again.
- **The agent's side** is its own: `rollback.json` is written before an apply
  with confirmation changes anything, and the agent rolls back an unconfirmed
  change at start. See *Commit-confirm* in AGENTS.md.

## Numbers

Keep these apart; each has one meaning.

| Number | Where | Rule |
|---|---|---|
| commit counter | `state.json` `last_commit` | +1 per commit attempt, **burned on failure** (`reserveNumbers`), so every document an agent sees has a unique number |
| firewall generation | `sessions.json` (`records.Generations`), sent as `Document.Generation` | per firewall, +1 per apply to it, burned on failure; the agent confirms by it (`/v1/confirm` must name the pending generation) |
| candidate generation | memory (`Store.CandidateGen`) | counts candidates set in this process; a cache key (`Server.view`), never stored |
| entry ids | `entry-ids.json`, `ids.json` | by path, kept across a rename, never reused; a copy or backup never lowers the highest given here |
| list ids | `ids.json` (`assignID`/`nextID`) | a list keyed by a numeric id gets the next one, never reused |
| HA epoch | the secondary's firewall row (`ha_epoch`), `fwconfig.HA.Epoch` | raised by a promotion; an agent that hears a primary peer at a higher epoch is stale and refuses older documents |
| deployment id | `deployments.jsonl` | the log's own counter (`next`) |

## Migrations

- **Tree shape**: `datastore.Migrate`, run by `Tree.UnmarshalJSON` wherever a
  whole tree is read (candidate, kept commits, copies, backups, bundles). Each
  migration is idempotent (a tree of this release's shape is left alone). The
  candidate is written back once migrated (`migrateHost`). Kept ids that move with
  the tree go through `datastore.MigrateIDPaths`. Since 1.0.0 a renamed or removed
  leaf needs one, plus old CLI/API paths kept for a release, and a test.
- **Directory layout**: `layout.json`. `checkLayout` refuses a directory of a
  higher layout, or one of before 1.0.0 (files or `portitor.db` but no
  `layout.json`: "update to 1.0.0 first"). A change of layout raises
  `layoutVersion` and keeps a reader of the old one for one release.
- **Copy format**: `copyFormat` (3) in a backup's or replica copy's manifest;
  `copyFormatOldest` (2) is still read. A copy without `global.json` or
  `entry-ids.json` is refused before anything changes.

## Rollback and revert

- **Commit-confirm** rolls back the *firewall* (the agent restores the last
  confirmed document). portitor-config's candidate is untouched, and the
  deployment is logged as `rolled_back`, so running is the previous live commit
  again.
- **Revert** (`Store.Discard`) sets the *candidate* back to running: the live
  commit's `deployed/<n>-config.json`. A document can't be turned back into a
  tree, which is why the tree is kept per commit.
- **Global lists** commit alone and at once (`commitScoped`). Their running state
  is `global.json`, so a rollback of a pending commit doesn't take them along.
- **Restore / replica copy** (`takeSnapshot`) replaces the candidate and
  `global.json` from the archive. A backup keeps this installation's own
  firewalls. Ids never go lower.
