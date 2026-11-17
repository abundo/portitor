<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# HA as a cluster: usability

The administrator should deal with a pair, not with leases and gates. Four parts,
in the order they are built. The code map stays in `arch-ha.md`, the user guide in
`docs/ha.md`.

## 1. The cluster summary

One view answers four questions: which host is active, is the standby ready, is the
configuration on both, can the pair fail over now.

What exists: `GET /v1/ha` (`agentapi.HAStatus`: state, term, peer alive, vote,
promise, watchdog, health, DHCP sync), the primary's `replication` (the replica's
copy), the witness setting. What is missing, added to the agent:

- **Each path's last answer** (`link_seen`, `mgmt_seen`): `beat` runs one goroutine
  per path but `answered` records only `peerSeen`. A pair running on one path still
  works, but has lost its redundancy: the summary must say so.
- **The witness's last ask** (`witness_seen`): `handleHAVote` records it. An active
  host whose witness hasn't asked for a while fails over by hand only.
- **The peer's release** (`peer_version`): the heartbeat carries `buildinfo.Version`
  both ways (an added `omitempty` field; an older peer sends none: "unknown").

The verdict is computed in portitor-config (`web/hasummary.go`), not the agent: the
replication status is the primary's portitor-config's, and `haStatus` stays cheap
and lock-free for the witness. Checks, each `ok`, `warn` or `fail` with a sentence:

| Check | fail | warn |
|---|---|---|
| active host | none active, or both | |
| standby ready | peer not heard, standby stale/fenced | peer's health below the active host's |
| paths | | one of the two paths silent for over `haDeadAfter` |
| witness | | no vote asked for in 10 s (failover by hand only); local witness (dies with the primary) |
| watchdog | none | softdog |
| configuration | not replicated | replica report older than 2 × `replicaEvery` |
| release | | the hosts' versions differ |
| DHCP sync | | an instance's sync has an error |

`failover-ready` is true when no check fails. In the merged agent status as
`ha_pairs` (global readers only) and in the state as the list `system/ha-pair`
(with its `checks`), so the CLI, NETCONF and SNMP get it too; the GUI shows it under
Admin → Firewalls (`HAPairs.vue`). Built.

## 2. Checks at join, and a switchover test

One YANG action `check` on a `firewall` that is an HA secondary (kind `view`, typed
output: a list of checks as above) run by `add-secondary`, the ISO's `--join`, the
portal's pairing and the GUI's *Check pair* button. Checks:

- both agents answer, each with the other's fingerprint;
- same release (refused: a secondary older than the primary can't copy);
- the secondary has every interface the primary's document uses, by name (see 3);
- the HA link: the peer answers on `fe80::1/2` over it; LLDP on it hears the peer's
  chassis id directly (a direct cable or a VLAN with no LLDP-speaking switch); a
  switch heard on both HA link and management is a warning ("may share a failure"),
  never a refusal: independence can't be proven;
- the witness answers from both hosts (`GET /v1/ha` with the witness secret);
- the watchdog: hardware, softdog (warning), none (failure: the host won't open on a
  vote).

The switchover test is a second action `test-switchover` (kind `operation`): checks
first, refused when not `failover-ready`; a switchover, wait until the other host
reports active, then one back (honouring the minute's damping: `handOver` from the
console path is not damped, monitoring is). It reports the time from the handover to
the peer's `active`, from the two agents' timestamps (gate opened), not a client's
outage, which it can't see.

Built (`web/hacheck.go`): `check` (the summary, interfaces, HA link by LLDP) and
`test-switchover`, in the GUI (Check pair, Test switchover), the CLI's `tools` and
NETCONF. Not yet: running `check` from `add-secondary`, `--join` and the portal's
pairing (the pair is only committed there, so the check comes after the first
commit); the witness asked from both hosts directly (the active host's
`witness_seen` stands for it).

## 3. Interfaces with other names on the secondary (later)

Decided 2026-11-17: the rename below, built later.

Not verified yet: that `PermanentMACAddress=` matches on the lab's virtio NICs, what
`agent.yaml` and the early policy name, and that a rename at runtime is safe while the
agent runs.


The pair runs one document by interface name (rules match `iifname`; MACs derive from
pair and name; conntrackd, monitoring). Mapping names per host would split that into
two documents or a translation in the agent. Instead the secondary's NICs are renamed
on the host to the primary's names:

- The mapping (secondary NIC → primary name) is chosen at join: by default the same
  name; the wizard lists the secondary's NICs by MAC, driver and carrier.
- The agent writes `/etc/systemd/network/10-portitor-<name>.link` (header
  `render.Generated`; only its own files touched) matching the **permanent** MAC
  (`PermanentMACAddress=`: the traffic NICs carry the pair's derived MAC once
  applied, so `MACAddress=` would stop matching after the first apply), and renames
  the device at once (`ip link set dev X down; name Y`, through `Runner`) when it is
  not in use.
- The HA link and management interfaces are renamed too, but last and only before
  the pair is made: renaming them later cuts the link the action runs over. Their
  names in `agent.yaml` (`early` policy) and `known-nics.json` follow.
- `POST /v1/nics/rename` (the pair's secret refused: token only), action `rename-nics`
  on the secondary's firewall.

## 4. A pair without an HA link (decided: no)

Decided 2026-11-17: (a), the HA link stays mandatory; `docs/ha.md` says why.

Not verified yet: the path the DHCP replication takes today (`replTarget`).


Safety, never two active hosts, is the leases and the witness's vote; the second path
only keeps a pair running when one network fails. Without an HA link a management
outage closes both hosts (no split brain). That is acceptable for a small office if
said plainly.

What uses the HA link today and would move to management:

- heartbeats: already on both paths, nothing to change;
- DHCP lease replication (`POST /v1/ha/dhcp`): HTTPS with the pair's secret, already
  fine over management;
- conntrackd: FTFW over UDP 3780 between link-local addresses, unauthenticated and
  unencrypted, per instance over a macvlan `ha-<id>` on the HA link. Over management
  it would expose the connection table to that network and accept injected entries:
  it needs a WireGuard tunnel between the hosts on management (the macvlans on top),
  or conntrack sync off.
- `builder` refuses a pair without both roles (`pairLinks`).

Options: (a) keep the HA link mandatory, document why; (b) optional, conntrackd over
an automatic WireGuard tunnel on management (medium: keys in the pair's rows, a
device, auto rules, docs); (c) optional, conntrack sync off without it (small; a
takeover drops connections). Recommendation: (c) now, (b) later if asked for.
