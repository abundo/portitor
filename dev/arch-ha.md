<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# HA pairs: the code map

Moved from AGENTS.md; keep it up to date with the code as AGENTS.md is.

**HA pairs** (`fwconfig/ha.go`, `internal/agent/ha.go`, `hastate.go`, `gate.go`,
`hamgmt.go`, `hatakeover.go`, `watchdog.go`, `web/witness.go`; design in
`dev/design-ha-cluster.md`): active/passive with the same addresses. A firewall may
be the HA secondary of another (`firewalls.ha_primary_id`, set at creation). It has
no instances of its own: `builder.BuildFirewall` builds the primary's, the same but
for `HA.Node` and the addresses on the pair's two links, physical interfaces of the
default instance with `Interface.HARole` (`pairLinks`): the HA link (a direct cable;
IPv6 link-local addresses by node, `fwconfig.HALinkAddress`, `fe80::1` and `fe80::2`,
a VF's `fe80::<id>:1`/`:2`, added `nodad`, never entered or discovered) and
management (`peer_addresses`, `HAGateway`, with the witness); a pair
without both is refused, and VRRP on one. Each physical traffic interface gets a
MAC shared by the hosts (`DeriveHAMAC`). The standby's traffic interfaces are closed
by the gate (`render.Gate`, netdev table `portitor_gate`, per namespace, on
`Instance.GateDevices`; LLDP passes); services run on both, and opening or closing
is one nft transaction, never an apply. A loop in `haManager` (no `Agent.mu`, so it
never waits for a commit) applies `haDecide` every `haTick`: a host stays open with
a vote (witness, `V` 4 s) or a promise (the standby's heartbeat answer, 2 s, either
path every 500 ms, `POST /v1/ha/heartbeat`); it opens with a vote once promises it
gave have run out and it hears no active peer; at start the primary opens on a
promise, so a healthy pair runs without the witness. It closes 1 s before its
leases end. A handover (`haManager.handOver`: monitoring, `portitor request ha
switchover`, a clean stop) gives up the vote, promises to stay closed as long as
that vote lasts, closes, and tells the peer (`POST /v1/ha/handover`), which opens at
once with the vote; the old host takes no vote until the promise ends
(`noVoteUntil`, also after a restart). `Interface.HAMonitor` counts a traffic
interface's carrier in the host's health, sent in heartbeats: when the standby has
more for 2 s the active host hands over, at most once a minute. With `HA.Preempt`
(the primary's `ha-preempt`, default true) an active secondary hands over to the
primary once it has heard it closed, at the pair's epoch and at least as healthy, for
30 s, after it went unheard since this host opened (`primaryLost`, so a switchover
stays) (`preemptSays`, `haShouldPreempt`): the configuration is edited on the primary. Each activation raises `term` (`<state>/ha-term`, separate from the
epoch). An open host arms `/dev/watchdog` (2 s, softdog if there is nothing better),
fed by that loop alone; with none, or `nowayout`, it won't open on a vote, only on
the console's (`portitor request ha active`). Apply loads the gate after moving a
device and before it comes up; `gate.check` looks for devices a closed gate lost
(6.12 detaches them) on each link event of a gated device (`gatewatch.go`) and
every second. So that a device something else brings up in that window passes
nothing, a closed gate has a second layer in the same transaction: `inet`, `arp`
and `bridge` tables `portitor_gate` (`render.GateFamilies`, priority -500, ahead
of defrag, conntrack and the raw chains) that drop by the names of the gate devices
and those stacked on them (`fwconfig.Instance.GateCover`, kept in
`gate.json.cover`); they hook the namespace, not a device, so nothing detaches
them, and they are deleted when the gate opens. A kernel that refuses them gets the
netdev gate alone, logged. Closed, a local send out a traffic interface fails with
`EPERM` (the netdev gate alone dropped it silently): the RA sender takes that as
held (`dhcpd.heldByGate`) and keeps its schedule; FRR may log send errors on a
standby. Packet sockets (the DHCPv4 client, GARP) pass the second
layer: in that window only the netdev gate would hold them. `dev/lab/gate-test.py`'s
`test_churn` measures it (`GATE_RULES`: the ruleset `render.Gate` emits,
`PORTITOR_GATE_OUT=<file> go test ./internal/render -run TestGate`). The host's own traffic uses table
`fwconfig.HAMgmtTable`: `from <management address>` always, and everything from
`iif lo` while closed (proto 99, `hamgmt.go`). At takeover (`onTakeover`): GARP and
NA twice, the DHCP server sends its initial RAs again (control op `advertise`), BGP is cleared. The witness
(`witness.vote`): every 1 s it asks both hosts in parallel and keeps its vote on the
host reporting active, else its holder; it moves only once the old holder's has run
out, plus `witnessGrace`, or at once to an active host that reports a vote, which
only a handover gives it. A pair has one witness (`firewalls.ha_witness` on the
primary): its portitor-config (`local`, `Server.runWitness`; not a replica's; it
dies with the primary, so failover is by hand), or `external`, portitor-web given
the pair's witness string (`web/portalwitness.go`, `WitnessPair`: both agents and
`ha_witness_secret`, which opens only `GET /v1/ha` and `POST /v1/ha/vote`,
`haManager.witnessAuth`). A commit skips an unreachable host whose peer answers
(deployment `skipped`), and the primary's portitor-config applies that commit's
document there when it answers again (`catchUp`). The DHCP servers run on both hosts;
the active host's agent sends each instance's leases to the standby's
(`internal/agent/dhcprepl.go`, see DHCP server). conntrackd
(`fwconfig.ConntrackSync`, `render/conntrackd.go`: FTFW over UDP 3780 into the
kernel table, between link-local addresses) runs per instance: the default instance's over the HA link, a VF's over
a macvlan on it in its namespace (`fwconfig.HASync`, `ha-<instance id>`). DHCP clients
run on the active host alone and pause on a closing one, keeping the address:
removing it would flush the masqueraded connections, here and through conntrackd on
the peer. Each static traffic prefix has a blackhole route at the highest metric
(`Instance.HABlackholes`), so a dead link's traffic doesn't leave by the WAN. The default instance
opens the ports of this host's agent and portitor-config to the peer, both ways
(`fwconfig.HAConfigAccess`, made by `Expand`; auto rules `render.HAConfigService`,
`HAAgentService`, `haOutputRules`). DNS updates and the tunnel broker run on the
active host only (`haManager.isStandby`, `Agent.reconcileActive`). ACME certificates
are ordered by the active host; the standby copies them, keys included, from
`GET /v1/ha/certificates` (the pair's secret, which therefore opens the keys too)
every minute (`certManager.adopt`, `acme.WriteRaw`), so it has them when it takes
over. `portitor show ha` and a firewall's form (Admin → Firewalls, *HA state*) show
`GET /v1/ha`, with each instance's DHCP lease sync (`Agent.haStatus`, which takes no
`Agent.mu`: the witness asks every second); The pair as one (`web/hasummary.go`, `pairSummary`, pure; design `dev/design-ha-usability.md`): from both hosts' `GET /v1/ha` (with each path's last answer `link_seen`/`mgmt_seen`, recorded by `beat` per path; the witness's last vote `witness_seen`; both releases, carried by the heartbeats), the witness setting and the copy (`configCopy`: the primary's `replication`, a replica's last copy), checks `ok`/`warn`/`fail` and `failover_ready`; in the merged status as `ha_pairs` (global readers) and in the state as `system/ha-pair`, shown by `HAPairs.vue` under Admin → Firewalls. The firewall's actions `check` (view: the summary from both agents asked now, with `interfaceCheck` and `haLinkCheck` over the live document) and `test-switchover` (operation: refused unless `failover_ready`, over and back with `switchSettle` between, timed until the other agent reports active) are `web/hacheck.go`. `POST /api/firewalls/:id/switchover`
hands the pair over from whichever host answers as active. The user guide is
`docs/ha.md`.
