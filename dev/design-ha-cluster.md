<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Design: HA cluster and a built-in DHCP server

Status: implemented, all six phases, and run on the lab pair, 2026-11-07. There are no
production systems, so no migration is planned.

## Goals

- An HA pair is one active host and one passive standby, with the same addresses
  and MAC addresses. VRRP is not used for HA.
- A host failure moves the LAN gateway and DHCP to the standby in under 10 s.
- The two hosts never forward or answer at the same time.
- Kea is replaced by a small DHCPv4/DHCPv6 server whose leases reach the standby
  as they change.

Not goals: more than two hosts, active/active, surviving the loss of both the
peer and the witness from one host, and relay, PXE or prefix delegation in the
DHCP server. VRRP stays as a feature for standalone firewalls and is refused on
a pair.

## Topology

Each host has its traffic interfaces and two more. Both are required for a pair,
and Portitor refuses a pair without them.

| Interface | Connects | Carries | On the standby |
|---|---|---|---|
| **HA link** | Direct cable between the hosts | Heartbeats, lease stream, conntrack sync, copies of certificates and lists | Up, own address |
| **Management** | Management network, with the witness | Witness votes, GUI and portal, updates, NTP, ACME, config replication, second heartbeat path | Up, own address |
| **Traffic** | LAN, WAN and so on | Everything else | Carrier up, gate closed |

The two paths must not share a failure. With quorum as "peer or witness", one
network carrying both means a switch failure fences both healthy hosts.

An external witness is required for automatic failover: the primary's own
portitor-config dies with the primary. With `ha_witness: local` a pair runs, but
failover is by hand (`portitor request ha active`).

## The gate

Every traffic interface of every instance is configured the same on both hosts:
addresses, routes, the ruleset and the services. What differs is a **gate**: a
`netdev` table in each namespace (`table netdev portitor_gate`) with an ingress
and an egress chain on the namespace's physical traffic interfaces, dropping
everything but LLDP. Only the lowest device needs it: a gate on the parent covers
its VLANs, and one on a port covers its bridge (tested). Tunnels should follow
from their underlay, which is not tested yet.

| Property | Why it matters |
|---|---|
| Carrier stays up | No wait for link-up or STP; link failures show on the standby |
| Nothing leaves | No duplicate MACs, ARP answers or IPv6 DAD conflicts |
| Services keep running | Takeover starts nothing: named, radvd, FRR and OpenVPN are up |
| A separate table | A commit reloads `inet firewall` and leaves the gate alone |
| One nft transaction per namespace | Opening and closing take milliseconds, where fencing today is a full apply |

**The gate is closed by default.** It is loaded before a traffic interface comes
up, so a booting or restarting host is closed until it decides otherwise. An
interface that exists before the gate stays down. This changes the apply order
for traffic interfaces on a pair: the device, then the gate, then up.

The kernel keeps a gate open across an agent restart, so a restarted agent
closes it before anything else, whatever it was. A kernel stall or an agent crash
leaves an open gate open. The watchdog covers
that (see [Watchdog](#watchdog)).

### The gate fails open on device changes

On Debian trixie's 6.12 a netdev chain holds a device only from when it is loaded.
A device deleted and made again is not gated, nor is one moved out of a namespace
and back, and both answer on the wire. A gate naming a missing device is refused.
Kernel 7.2 behaves differently on all three, so `dev/lab/gate-test.py` must be run
on each kernel the ISO ships. The agent therefore:

- **Loads the gate after every move and before every up,** in the device's
  current namespace. The kernel takes a device down when it moves, so the order
  move, gate, up leaves no window.
- **Reloads the gate whole,** in the same apply, for each namespace whose devices
  changed.
- **Checks the gate** every second while closed. A traffic interface a closed gate
  doesn't hold is set down, the gate loaded again and the interface brought back. On
  6.12, `nft -j list table netdev portitor_gate` shows only the devices a chain really
  holds: as a list, a string when one is left, and no `dev` when none is (measured).
  One second of polling leaves a window after a device change no apply made, such as
  a driver reset. A netlink watch can close it (`linkwatch.go`).
- **Falls back to setting devices down** when nft can't close the gate. If that fails
  too, the watchdog stays armed and unfed, so the host resets.

A closed gate returns `ENOBUFS` to `AF_PACKET` sends, so a sender on the standby
must treat that as normal.

### Same MAC on both hosts

The builder derives a locally administered MAC per traffic interface from the
pair and the interface name (`Interface.MAC`), so ARP caches stay valid after
a takeover. Replies still go out at takeover, to update switches. Hypervisors
must allow changed MACs (Proxmox MAC filter, VMware forged transmits).

### The standby's own traffic

The default instance's main table points at the gated WAN. The agent keeps a
table `ha_mgmt` with the management gateway, a rule `from <management address>
lookup ha_mgmt` on both hosts, and on the standby alone a catch-all rule for what
the host itself sends (proto 99). NTP, apt, ACME and syslog then work on the
standby. Forwarded traffic isn't affected, as the gate drops it.

### Per-host values

`peer_priority`, `peer_router_id`, `peer_net` and `ha_peer_address` are removed,
and with them `peerValues` for everything but one case: `peer_addresses` stays,
for the management and HA link interfaces alone. Both hosts otherwise get the same
document, apart from `HA.Node`.

## Who is active

Two kinds of lease decide. A lease is a promise with an end time, counted from
**before** the request that got it was sent by the holder, and from **after** the
call returned or failed by the grantor. So a holder always thinks it ends first.

- **Vote** (`V` = 4 s): from the witness, to one host at a time.
- **Promise** (`P` = 2 s): the standby's heartbeat answer, "I stay closed for
  `P`", sent on either path every 500 ms.

Rules:

1. **Stay open** while the host holds a vote or a promise. A host holding neither
   closes at once.
2. **Open** only with a vote, when every promise this host gave has run out and it
   hears no active peer, or on a handover from the peer. The last condition isn't
   needed for safety, as the leases already close the old host (mutating it fails no
   simulation), but it avoids needless flapping.
3. **At start,** with neither active, the primary opens when it holds a promise.
   So a healthy pair runs without its witness.
4. **Stale:** a host that hears a higher term closes and becomes the standby.

The active host closes `M` = 1 s before its leases end, so it is closed in time
even if `nft` is slow. A closing host keeps reporting active until its gate has
closed. A restarted host waits `P` before it may open, as it forgot what it promised.

A promise is given only to an active peer, or by the secondary to the primary at
start. If a primary promised a closed secondary too, neither would ever open.

### States

```
          boot
           |
           v         vote or handover, promises run out
       STANDBY ---------------------------------> ACTIVE
           ^                                        |
           |   higher term, handover, leases end    |
           +----------------------------------------+
```

`STANDBY` covers fenced too: a host without quorum and a healthy standby are both
closed, and differ only in what they report. `Fenced` and `Standby` in `HAStatus`
become `State` (`active`, `standby`, `fenced`, `stale`).

Each activation raises `term` (persisted, the highest seen plus 1), carried on
heartbeats and the lease stream. This is separate from `ha_epoch`, which counts
config promotions.

### What the witness changes

Votes today go to "a host", which only allows being active. Now a vote names the
active host:

- The holder is the host reporting `State: active`, ahead of everything else. A
  witness that restarts must not hand the vote to the primary while the secondary
  is active.
- A vote moves only when the old holder's has run out, plus `G` = 1 s, also when
  it moves towards the active host: a leftover vote could otherwise open the other
  host. The active host relies on its promise meanwhile.
- Hosts are asked in parallel, every 1 s, with a 500 ms timeout.
- `pv.until` is set after `HAVote` returns, and on an error too, so a host's vote
  can't outlast the witness's record (done). `G` covers a request still in flight
  after a timeout.

### Failure table

| Failure | Result |
|---|---|
| Active host dies | Vote runs out, standby gets it and opens |
| HA cable | Heartbeats go over management; replication stops, with an alert |
| Management switch | Hosts hear each other; active stays; alert |
| HA cable and management switch | Active holds no lease and closes; standby can't get a vote; **both closed** |
| Witness | No change; alert |
| Active loses witness and standby | Closes; standby takes over if it has the vote |
| Witness can't reach active, hosts fine | Standby may get the vote but hears the active host's heartbeats, so stays closed by rule 2 |
| Agent crash or hang on the active host | Watchdog resets the host |

### Failure budget

Worst case, a crash just after a vote renewal:

| Time | Step |
|---|---|
| 0 s | Crash |
| 4 s | Vote ends |
| 5 s | `G` passes |
| 6 s | Next witness round grants the vote |
| < 7 s | Gate opens, GARP and NA go out, DHCP answers |

The figure covers the LAN gateway and DHCP. BGP and OSPF add their own time.

### Watchdog

The agent arms `/dev/watchdog` when it opens the gate and disarms it when it
closes. Timeout `W` = 2 s, fed from the HA loop alone, which touches no disk.
`W + M < V` is checked at start.

A hardware watchdog covers a kernel hang; `softdog` covers only an agent hang.
The agent reports which one it has, and loads `softdog` if there is nothing else.
No watchdog at all, or one with `nowayout`, refuses automatic failover: only the
console's vote opens such a host. On Proxmox, use the `i6300esb` device.

**Agent restarts** count too. On a clean stop the active agent closes the gate; the
handover to its standby comes with phase 4. So an update of the active host costs a
short interruption, and updates go to the standby first.

## Interface monitoring

`interfaces.ha_monitor` (per interface, on by default for physical traffic
interfaces) counts in the host's health, sent in heartbeats. When the standby has
more monitored interfaces with carrier for 2 s, the active host hands over.

**Handover:** the active host gives up its vote, promises to stay closed for as long
as that vote lasts (at least `P`), closes, and only then tells the standby, which
opens at once, holding the vote and a promise. It is used for monitoring, `portitor
request ha switchover` and a clean stop. Three rules keep one vote at a time, and the
simulation finds both hosts open without the first two:

- The promise lasts as long as the vote it hands over. A 2 s promise let the old host
  open on a vote the witness had renewed while the new host still held its own.
- A host that handed over takes no vote until that promise ends, nor does a restarted
  host for `V`, as it may have forgotten handing over. The witness can't ask the new
  host and renews the old one otherwise, and later both hold a vote. The console's vote
  is exempt.
- The witness renews at once for an active host that reports a vote, rather than
  waiting for the old holder's to run out: only a handover gives it one, and the old
  host may be stopping. A new host on a promise alone would close again after 1 s.

Damping: after a monitored handover, that host hands over no more for 60 s. It is per
host on purpose. A single flapping link can't loop, as there is no failback, so a pair
moves at most there and back and then stops; a rule for the pair would leave traffic on
a host whose LAN has died. A pair with equal counts stays where it is. There is no automatic failback at all; `portitor request ha
switchover` moves the traffic by hand.

## What each service does

| Service | Standby | At takeover |
|---|---|---|
| nftables, routes, addresses | Applied | Nothing |
| Gate | Closed | Opened |
| GARP and unsolicited NA | None | One per address, repeated once after 1 s |
| DHCP server | Passive, applying the stream, no sockets | Goes active |
| DHCP clients on the WAN | Paused, keeping the lease and address; never active on the standby | Renew. The server knows the shared MAC, and the DUID is made from it, so nothing is replicated |
| radvd | Running | Sends at once |
| named, chrony, snmpd | Running | Nothing |
| FRR | Running, no neighbours | Sessions cleared, so BGP doesn't wait for its retry timer; OSPF waits for hellos |
| WireGuard, OpenVPN | Running, same keys | Peers reconnect |
| conntrackd | Writes the peer's connections to the kernel table | Sends |
| ACME, DNS update, tunnel broker | Off (`haManager.standby`, today) | On |
| IP lists, DNS blocklists | Download from the host, over management | Nothing |

`render.Options.Fenced` and `fence()` go: nothing renders differently on the
standby, so previews match on both hosts.

### Conntrack into the VFs

conntrackd runs per namespace, and the HA link is one interface in the root
namespace. Each VF gets a macvlan device on the HA link, in its namespace
(`fwconfig.HASync`, `ha-<instance id>`, names may not start with `ha-`), with an address
in a `169.254.16.0/20` and up /30 by instance id, so no column keeps it. VLANs were
planned, but tagged frames may not survive a hypervisor's access port, and a macvlan
works on a cable and a VM NIC alike. The default instance uses the link itself.

### A closing host keeps its addresses

Removing a WAN address makes the kernel flush the connections masqueraded to it, and
conntrackd then flushes them on the host that took over. A client that still sends
recreates them mid-stream, which hid this in tests of a switchover; a connection with
only the server sending dies. So DHCP clients pause on a closing host (`Pause`) and
keep the address behind the gate.

### Last-resort routes

A dead link takes its connected route with it, and traffic for its clients would follow
the default route out of the WAN, with private addresses, until the standby takes over.
Each static prefix of a traffic interface has a blackhole route at the highest metric
(`Instance.HABlackholes`), used only then.

## Config roles stay

Primary and secondary (who owns the database) stay separate from active and
standby (who forwards). A failover changes no database: the replica stays
read-only until promoted (`promote`, unchanged but for dropping `swapHAValues`).
The GUI shows both roles. A commit from the primary applies to the active and
standby hosts alike and never touches the gate.

## DHCP server

### Process

`portitor-agent dhcpd <instance>`, through `netns-exec`, one per instance with
DHCP, in units sandboxed like today's Kea units. It runs as an unprivileged user
with `CAP_NET_BIND_SERVICE`, and `CAP_NET_RAW` for its address checks and neighbour
solicitations. The agent, as root, never parses a client's packet.

- It reads a rendered config (`dhcpd.json`, from `internal/render`, as pure as the
  rest) and reloads on SIGHUP without dropping leases or state.
- It has a Unix socket to the agent, for leases, the mode (active or passive) and
  the stream. This replaces `parseKeaLeases`.
- It sends with a UDP socket bound to the interface and broadcasts to clients
  without an address (`server4` does the same, and Kea does on platforms without
  direct replies). A raw socket or ARP injection comes in only if the lab shows
  clients that need it.
- DHCPv6 uses a UDP socket per interface, joining `ff02::1:2`.

### Leases

An append-only log per instance with periodic compaction, in the unit's state
directory, fsynced before the reply to a new binding. Written by this process
alone.

### Replication

The stream runs `dhcpd` → agent → (HA link, the pair's secret, pinned) → agent →
`dhcpd`. Records are ordered per instance, with sequence numbers and `term`.

- **New bindings** wait for the standby's ack, for at most 100 ms, and not at all
  while the peer is gone.
- **Renewals** are batched, at most every second.
- **A rejoining standby** gets a snapshot, then the stream.
- **Records of a lower term** are refused.

### Server identity

The DHCPv4 server id is the shared interface address. The DHCPv6 server DUID comes
from the document (`DHCPServer.DUID`, made once by the builder), so renewals
reach the new active host.

### Client behaviour

From Kea's and dnsmasq's source, each with a table-driven packet test.

Parsing, in a tolerant layer over `insomniacslk/dhcp`, which rejects packets for
two of these:

- A truncated option ends parsing and keeps what came before.
- A missing End option is accepted.
- Repeated options are concatenated (the library does this).
- An empty hostname option is dropped.
- A hostname's trailing NUL is dropped (the library does this).
- Overloaded `file` and `sname` fields are read (the library doesn't).

Replies:

- The message type comes first, and the library doesn't do this.
- Size is capped by option 57, default 576 bytes, and padded to 300.
- The client id is echoed.
- A reply to the broadcast address uses the broadcast MAC.
- A NAK is broadcast; a DHCPINFORM without `ciaddr` goes to the packet's source.
- T1 has random jitter.
- A generated hostname has no trailing dot.

Requests:

- A DHCPREQUEST without a requested IP and `ciaddr` gets an address and an ACK.
- A DECLINE or RELEASE without a server id is accepted.
- `ciaddr` is cleared on a DISCOVER or with a requested IP.
- A lease is found by client id, then MAC, and a known client id is reused for a
  request without one.
- A DECLINE counts only for a valid lease of that client.
- Requested lease times have a 120 s minimum.

Allocation:

- `.0` and `.255` are never handed out dynamically.
- Before an OFFER, the address is checked for use, except when that client already
  has its lease. Results are cached, and checks stop under load.
- **After a failover,** a renewal for an unknown address that is free is accepted,
  not NAKed, so a lost record doesn't drop a client.

DHCPv6:

- A reservation's MAC comes from the neighbour table, with a solicitation and
  retries for up to 500 ms, then a DUID of type 1 or 3, then an EUI-64 link-local
  address.

### Scope

Pools, gateway, DNS, domain, option 108, MAC reservations and several subnets on
an interface: what Kea does in Portitor today, no more.

## What goes away

- Kea: packages in `install.py` and `iso/preseed.cfg`, `deploy/systemd/portitor-kea*`,
  `deploy/apparmor/usr.sbin.kea-*`, `internal/render/kea.go`, `DHCPHA`, ports 8001
  and 8002, `moveDefaultInstance`'s Kea part and `kea_*` paths.
- `peerValues` and its columns, `haLink`, `fence()`, VRRP's HA use and
  `swapHAValues`.
- `started` in `Agent`, the first-apply restart of Kea.

## Phases

Each phase ends with passing tests, and phase 2 can ship without phase 4.

1. **Prove the gate.** Done for the packet path, see below. Still open: FRR and
   radvd behind a closed gate, tunnels, and a real NIC (the tests use veth).
2. **Fix the witness bug.** Done.
3. **Cluster core.** Done, and run on the lab pair. See below.
4. **Monitoring and services.** Done, and run on the lab pair. See below.
5. **DHCP server.** Done, Kea removed, and run on the lab pair. See below.
6. **Docs and GUI.** Done: `docs/ha.md` rewritten, `docs/vrrp.md`, AGENTS.md,
   Admin → Firewalls (*HA state*, *Switch over*) and `portitor show ha` (DHCP lease
   sync).

### Phase 3 notes

Built: interface roles (`ha_role`, `ha_gateway`), shared MAC addresses, the gate, the
leases and states, the term, the watchdog, management routing, GARP and NA, DHCP
renew, radvd and BGP at takeover, the witness changes, heartbeats on both paths, and
VRRP's removal from pairs with its `peer_*` values.

Until later phases:

- **Kea has no HA hook.** Hot-standby can't work here: its primary role would refuse
  to serve from the standby-role host while the other, closed, still answers on the
  HA link. So each host's Kea runs alone with its own leases until phase 5, and
  clients may see a NAK after a takeover.
- **The HA link's addresses are entered by hand,** like management's.
- **The witness needs a way in.** An external witness calls the agent's port, which
  only `allow_from` opens. Its address must be listed in `agent.yaml`.

### Phase 5 notes

What the build changed from the plan above:

- **The DHCPv4 wire format is Portitor's own** (`dhcpd/packet4.go`), not a layer over
  `insomniacslk/dhcp`: most of the tolerance list is in the parser, and the reply
  rules (message type first, size cap, padding) in the writer. DHCPv6 uses the
  library.
- **No active or passive mode.** The standby's gate is closed, so its server hears no
  client; it only takes the stream.
- **The server DUID comes from the instance's name** (`render.DHCPServerDUID`, a
  DUID-UUID), the same on both hosts, with no column.
- **The ARP check returns who answers.** An address another host answers for is held
  from offers for 10 minutes, but the client answering for it itself keeps it. After a
  failover, a client the new host has no record of renews without a NAK, and a new
  client isn't given that address. The first build held the address from everyone,
  which moved a client to a new address in the lab.
- **The agent sends the stream.** It long-polls the server's changes over the control
  socket, so the server has no network access beyond DHCP. Merging is by the time of
  the change, the newer copy winning, so a snapshot and the stream can overlap.
- **The config is in a directory per instance** (`/etc/portitor/dhcpd/<name>/`): a
  file's bind mount keeps the inode that the agent's rename replaces.

### Phase 5 lab results

On the lab pair, with client1 and a test client in a network namespace with its own MAC
address:

| Test | Result |
|---|---|
| A renewal of an address Kea had given, unknown to the new server | Granted |
| A new client | Offered after the 300 ms ARP check, bound; the same address again in 1 ms |
| A host using a free address without a lease | Skipped, the next address offered |
| A switchover before replication, then a new client and a renewal | The new client was kept off the renewing client's address, and the renewing client kept its address |
| DHCPv6 (a temporary ULA prefix, RA with the M flag) | client1 got an address, valid 86400 s, preferred 64800 s |
| A new binding with replication | On the standby before the client's ACK, at a cost of milliseconds |
| A switchover with replication, then a renewal | Granted at once, with no ARP check: the new host has the lease |

Not tested on the lab: reservations, a hard reset during a new binding, clients other
than Linux (NetworkManager and the test client).

### Phase 4 lab results

As in phase 3, with a TCP download through the pair held open across each event.

| Event | Outage | Download |
|---|---|---|
| `portitor request ha switchover` | One ping lost at most | Survives |
| Clean restart of the active agent | One ping lost at most | Survives |
| Active agent stopped for 8 s | One ping lost at most | Survives |
| Monitored LAN carrier lost on the active host | 2.7 to 2.9 s, the 2 s hold included | Survives |
| Active host hard reset | 5.0 s; 5.6-5.7 s on the final build | Survives |
| Carrier lost on the standby | None | Not tested with a download |

Each VF gets its device and conntrackd exchanges keepalives through it. A VF's
connections surviving a failover isn't tested: the test VF had no traffic.

The live runs found what the Go tests couldn't: the handover needs the vote (a new host
on a promise alone closed again and the pair flipped twice), masquerade flushes
connections when a closing host loses its address, and traffic for a dead link's clients
left through the WAN. The simulation, given handovers, found two ways to both hosts open
before they reached the lab. It passes 300,000 runs. A restart waiting `V` rather than
`P`, and the old host clearing its vote, aren't needed in it; they stay as margins.

### Phase 3 lab results

Two Debian 13 VMs on Proxmox, kernel 6.12, softdog, on the VLANs of
`docs/portitor-ha.drawio`, the witness on `.7`, WAN by DHCP, and a client pinging its
gateway and the Internet through the pair every 100 ms.

| Failure | Outage | Result |
|---|---|---|
| Active host hard reset (sysrq) | 4.9 s, 5.2 s, 5.4 s | Standby opens on the vote; the old host returns as standby |
| Agent hung on the active host (SIGSTOP) | 3.1 s | Softdog resets the host |
| Clean stop of the active agent (update) | 3.0 s | Traffic moves or returns |
| HA cable cut on the active host | None | Heartbeats over management |
| Management cut on the active host | None | Vote moves, standby stays closed by its promise |
| Witness stopped | None | Votes end, promises hold the pair |
| Both links cut on the standby | None | Standby fenced |
| Both links cut on the active host | 2.6 s | It closes, then the standby opens |
| Both links cut on both | As long as the cut | Both closed, as designed; recovers alone |
| Device moved behind a closed gate | None | `gate.check` closes it and brings it back up |
| Commit on the running pair | None | Gates untouched |

Both gates were sampled through the link cuts and were never open together. The
Internet recovers with the gateway. Live runs found three bugs no test had: the second
round of announcements ran on a cancelled context, a WAN DHCP client stayed in its old
renewal for 15 s after a takeover, and `gate.check` left a device down that the kernel
had taken down by moving it.

Not covered: a hardware watchdog (`i6300esb`) and a kernel hang, a real NIC and
switch, and a Proxmox host or switch failure, as both VMs run on one node. The
standby's own traffic works: it reaches the Internet through the management gateway.
The two hosts' gates can't be read at the same instant, and
sampling runs through SSH, so "never both open" is a sample, not a proof.

### Phase 1 results

`dev/lab/gate-test.py`, in namespaces on lab host .6 (Debian 13, kernel 6.12.113,
nft 1.1.3) with controls for each case, and locally on 7.2.14:

| Check | 6.12 |
|---|---|
| Closed: no reply to ping or ARP, nothing on the wire, carrier up | Pass |
| Gate before up: no DAD, MLD or RS leaves, DAD passes with the address in use | Pass |
| `AF_PACKET` send dropped, with `PACKET_QDISC_BYPASS` too | Pass, returns `ENOBUFS` |
| `AF_PACKET` socket bound to one ethertype, receiving behind a closed gate | Sees nothing (`ETH_P_ALL` not tested) |
| LLDP both ways | Pass |
| VLAN on a gated parent, bridge on a gated port | Pass |
| `inet firewall` reloaded as a commit does | Gate unaffected |
| Device recreated, or moved away and back | **Fails open** |
| Open or close, 16 interfaces, one namespace | 24 ms median, 36 ms worst |
| One MAC on a switch before takeover | One FDB entry |
| Takeover under pings every 10 ms, with GARP | 4 of 500 lost |
| Takeover without GARP | 7 of 500 lost on 6.12; 18 and 266 in two runs on 7.2 |

Takeover here is the gate step alone, after the vote has moved. GARP stays
required: without it the loss varies widely, and on a real switch it lasts until
the standby sends something.

## Tests

- **Unit:** the state rules as pure functions over leases and a fake clock, every
  row of the failure table, and property tests that no two hosts are ever open.
- **Packets:** a table per client behaviour above.
- **End to end:** `iso/test-ha.sh` on QEMU, with two hosts, a witness and a client,
  killing a host, cutting each link, hanging the agent and measuring failover.
- **Lab:** Windows, macOS, iOS, Android, Linux, printers and IoT on the lab hosts.

## Risks

| Risk | Plan |
|---|---|
| The gate doesn't hold on device changes | Measured on 6.12, handled in [The gate fails open on device changes](#the-gate-fails-open-on-device-changes); a 1 s window remains for a change no apply made |
| The gate doesn't hold on real NICs | Repeat the test on a lab NIC |
| A hung kernel on a VM with only softdog | Reported in the GUI; use a hardware or emulated watchdog |
| A false reset from an I/O stall | The HA loop touches no disk; tune `W` in the lab |
| FRR misbehaves with no neighbours for days | Test in the lab; else stop it on the standby and accept the start time |
| 4 s votes flap on a poor management network | Hosts stay open while they hear each other, so a vote only matters with the HA link down too |

## Open questions

- How should a third-party daemon started by a task behave on the standby?
- How are IPv6 addresses learned upstream (a WAN router's neighbour cache) refreshed
  when the router ignores unsolicited NA? The shared MAC should cover this.
