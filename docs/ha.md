<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# High availability (HA pairs)

Two firewalls can run as an **HA pair**: one **active** host forwards and answers for
the pair's addresses, and a **standby** with the same configuration waits to take over.
The two have the same addresses and the same MAC addresses on their traffic
interfaces, so when the standby takes over, the clients keep their gateway, their
DHCP leases and their open connections.

- **Every commit goes to both.** A change is applied to the two hosts together, waits
  for confirmation on both, and is rolled back on both if either fails.
- **Only one host is open.** The standby's traffic interfaces stay up but closed: it
  sends and takes nothing on them. A host opens only with a vote from a third party,
  the **witness**, or when its peer hands over, so two hosts that can't hear each
  other never both answer for the same addresses.
- **State follows.** DHCP leases, open connections and ACME certificates are copied to
  the standby as they change.
- **The configuration survives.** portitor-config on the primary holds the pair's
  configuration; the secondary's keeps a read-only copy, and can be **promoted** when
  the primary is lost.

**Primary and secondary** say who owns the configuration. **Active and standby** say who
forwards. Either host can be active; a failover changes no configuration.

## What you need

- **Two firewalls with the same interface names** (`ens18`, `ens19`, ...). The
  secondary runs the primary's interfaces by name.
- **Two interfaces of their own on each host**, besides the traffic interfaces:
  - the **HA link**, a direct cable between the hosts (or a VLAN only they share);
  - the **management** interface, on a network of its own, with the witness, the GUI
    and the host's own traffic (updates, NTP, ACME, DNS blocklist downloads).

  The two must not share a failure: with one switch carrying both, losing that switch
  would close both healthy hosts.
- **portitor-agent and portitor-config on both** (`install.py --agent HOST` installs
  both).
- **An external witness** for an automatic failover: portitor-web on a third host on
  the management network, usually the portal ([HA pair and
  portal](deployments.md#ha-pair-and-portal)). Without one, the primary's
  portitor-config is the witness and goes with the primary: the pair still never has
  two active hosts, but losing the primary takes a step by hand (see [The
  witness](#the-witness)).
- **Hypervisors that allow changed MAC addresses** on the traffic interfaces (Proxmox's
  MAC filter off, VMware's *forged transmits* on), as both hosts use the pair's MAC
  addresses.
- **A watchdog.** The active host arms one, so a hung host resets and the standby
  takes over. The agent loads `softdog` if there is nothing better, which covers a
  hung agent but not a hung kernel; on Proxmox, add the `i6300esb` watchdog device.
- **conntrackd** on both (`install.py` installs it).

## Setting up a pair

Everything is done in the primary's portitor-config.

1. **The two links.** On the primary's host, under *Network → Interfaces*, give one
   physical interface the *HA role* *HA link* and another *Management*. Each gets its
   address(es), and under *HA peer addresses* the secondary's, in the same prefix and
   order (`169.254.1.1/30` and `169.254.1.2/30` on the HA link). The management
   interface also gets its *Management gateway*, which the host uses for its own
   traffic while its traffic interfaces are closed; it must not be the pair itself.
2. **The primary's agent URL** under *Admin → Firewalls* is its management address
   (`https://172.25.38.1:8443`), not `127.0.0.1`: the secondary and the witness use it.
   Set its *portitor-config URL* (`https://172.25.38.1:8444`) and *fingerprint*
   (`portitor-config fingerprint` on it), for the secondary to copy from.
3. **The secondary**: *New firewall*, with its agent URL (its management address),
   token and fingerprint (`portitor-agent init` there prints them), its
   *portitor-config URL* and *fingerprint*, and *HA secondary of* the primary. This can
   only be chosen when the firewall is created. The secondary has no virtual firewalls
   of its own: it runs the primary's.
4. **The witness.** On the primary, set *HA witness* to *External* and copy the
   *Witness string* to the third host (see [The witness](#the-witness)).
5. **Commit.** Both hosts get the configuration; confirm it as usual.

A commit lists what is missing (`HA: interface ens20: the secondary needs an address of
its own for each address (peer addresses)`). The agents reach each other on their HA
link addresses and their management addresses, both on the agent's port: in each
`/etc/portitor/agent.yaml`, `listen` on all addresses (`":8443"`), and `allow_from`
the peer's and the witness's addresses.

Everything else (traffic interfaces, rules, routes, services, virtual firewalls) is
the same on both hosts. VRRP is refused on a pair: the pair shares its addresses
itself.

From that commit on, the secondary's portitor-config is a **replica**: it copies the
primary's database every 15 seconds (when it changed), users included, and refuses
changes. Its GUI shows an *HA secondary* badge with the last copy. Log in there with
the primary's users.

## Who is active

The hosts send each other heartbeats every half second, over the HA link and over
management. Two kinds of lease decide which host is open:

- **The witness's vote** goes to one host at a time, for 4 seconds, renewed every
  second while that host answers. It follows the active host.
- **The standby's promise** to stay closed, for 2 seconds, comes back with each
  heartbeat answer.

The active host stays open while it holds either. A host opens only with the vote,
once the promises it gave have run out and it hears no active peer, or when its peer
hands over. A healthy pair needs no witness to run: at start the primary opens on the
secondary's promise.

| What fails | What happens |
|---|---|
| The active host (power, kernel, hung agent) | Its vote runs out and the witness gives it to the standby, which opens: about 6 seconds. A hung agent or kernel is reset by the watchdog. |
| A monitored traffic interface on the active host loses its carrier | The standby has more monitored interfaces with a carrier for 2 seconds: the active host hands over (about 3 seconds). |
| The HA link | The heartbeats go over management. Nothing moves. |
| The management network | The hosts hear each other over the HA link. Nothing moves. |
| The witness | Nothing moves while the hosts hear each other. |
| Both links, from the active host | It can't renew its leases and closes; the standby opens with the witness's vote. |
| The HA link and management together | The active host closes; the standby can't get the vote: **both closed** until one comes back, or [by hand](#on-the-console). |

**Interface monitoring.** Physical traffic interfaces are monitored by default (*HA
monitor* on the interface); turn it off for one a failover wouldn't help. After a
monitored handover, that host doesn't hand over again for a minute, so a flapping link
moves the traffic there and back at most.

**There is no automatic failback.** A host that comes back joins as the standby. Move
the traffic by hand with *Switch over* under *Admin → Firewalls* (on either host's
form), or `portitor request ha switchover` on the active host.

**Handover.** A switchover, a monitored handover and a clean stop of the active agent
(an update, a reboot) hand over: the active host closes and the standby opens at once,
taking the vote. Clients lose a packet or two. A host that restarts comes up closed.

**At takeover** the new active host sends gratuitous ARP and unsolicited neighbour
advertisements for every address, twice, router advertisements at once, and clears
its BGP sessions so they come up without waiting for a retry timer. OSPF waits for its
hellos.

In the lab, with a download through the pair held open across each event:

| Event | Outage | Download |
|---|---|---|
| Switchover | One ping lost at most | Survives |
| Clean restart of the active agent | One ping lost at most | Survives |
| A traffic interface's carrier lost on the active host | 2.7 to 2.9 s | Survives |
| Active host hard reset | 5 to 6 s | Survives |

## What the pair keeps in step

| | How |
|---|---|
| **Configuration** | Kept by the primary's portitor-config, copied by the secondary's. Every commit goes to both hosts. If one can't be reached and the other can, the commit goes to the reachable one, and the other is shown as *skipped*: it gets the commit as soon as it answers again. |
| **DHCP leases** | The active host sends every change to the standby over the HA link: a new lease is on the standby before the client gets its answer, renewals within a second. A standby that missed changes gets all the leases first. After a takeover, a client that renews an address the new host doesn't know keeps it, and a new client is never given an address another host answers for. |
| **Connections** | conntrackd sends each host's connections to the other, which keeps them in its own table, so connections through the firewall live on after a takeover. Each virtual firewall syncs over a device of its own on the HA link. Connections to the firewall itself (SSH to it, say) end there. |
| **DHCP clients** (a WAN by DHCP) | Run on the active host only. The standby keeps the lease and address behind its closed interfaces, so masqueraded connections survive; the new active host renews it, with the same MAC address and DHCPv6 DUID. |
| **ACME certificates** | The active host orders and renews them; the standby copies them every minute, so it has them when it takes over. |
| **DNS updates, tunnel broker** | Only on the active host, so the two never publish their addresses in turn. |
| **IP lists, DNS blocklists** | Each host downloads them over management. |

Services (DNS, NTP, router advertisements, FRR, WireGuard, OpenVPN) run on both hosts;
the standby's are behind its closed interfaces, so a takeover starts nothing.

Each static traffic prefix has a blackhole route at the highest metric, so traffic for
the clients of a dead link isn't sent out of the WAN while the standby takes over.

## The witness

A pair has one witness, never two: two could each vote for another host.

- **External** (*HA witness*: *External*): portitor-web on a third host on the
  management network, which may be the portal or not. Set it on the primary under
  *Admin → Firewalls*, commit, and copy the *Witness string* (or `portitor-config
  witness-string` on the primary's console) into `/etc/portitor/web.yaml` on the third
  host:

  ```yaml
  witness:
    - portitor-witness:eyJwYWlyIjoi...
  ```

  `portitor-web start` (the portal) is then the witness too; `portitor-web witness`
  is the witness alone, without the GUI. The string holds both agents' URLs and
  certificate fingerprints, and the pair's witness secret, which opens nothing on the
  agents but the state and the vote. The agents must let the third host in
  (`allow_from`).
- **The primary's portitor-config** (*HA witness*: *This firewall's portitor-config*,
  the default). Nothing else to run, and the pair never has two active hosts. But it
  goes with the primary: when the primary is lost, the secondary stays closed until you
  open it by hand (`portitor request ha active`) and
  [promote](#promoting-the-secondary) it.

## On the console

On either host, as root:

```
portitor show ha                          # state, peer, vote, monitored interfaces, watchdog, DHCP lease sync
portitor request ha switchover            # on the active host: hand over to the standby
portitor request ha active --minutes 60   # break glass: open without the peer or the witness
```

`portitor request ha active` is for a host that hears neither its peer nor the witness
(both links down, the witness gone). It is logged. Never use it while the other host
may still be running: both would answer for the same addresses.

*Admin → Firewalls* shows each host's role and state in the *HA* column; a host's form
has the same as `portitor show ha` under *HA state*, with *Switch over*.

## Updates

`./install.py` updates a pair one host at a time, the secondary first. Each agent
restart hands over cleanly, so clients lose a packet or two at most each time.

## Promoting the secondary

When the primary is lost (dead hardware, a site gone), promote the secondary: its
copy of the configuration becomes the pair's.

- In the secondary's GUI: the *HA secondary* badge in the top bar, then *Promote* (a
  global admin). Or on its console: `sudo -u portitor portitor-config promote`.
- It is refused while the secondary's agent hears the primary: promote only a
  secondary whose primary is gone. `--force` (or *Force* in the GUI) promotes anyway;
  then both believe they own the configuration until the old primary is caught up.

The promotion swaps the two hosts in the configuration: the virtual firewalls and
tasks move to the secondary, the HA link and management addresses swap with their
*HA peer addresses*, the old primary becomes the secondary, the pair's **epoch** goes
up, and it commits. The commit skips the old primary while it is away.

When the old primary comes back, it hears its peer answer as primary at a higher epoch:
it has been taken over, so it stays closed (*stale*) and refuses configurations of the
earlier epoch. Its portitor-config becomes a replica of the new primary, which then
catches it up, and it takes part as the secondary. To drop it instead, delete it under
*Admin → Firewalls* and add a new secondary later.

Lost with the primary: changes made there since the secondary's last copy, and the
*Revert* snapshots (Revert works again after the next commit).

## Troubleshooting

- **Both hosts show *peer: not heard*.** The heartbeats go to the agent on the peer's
  HA link and management addresses: check `listen` and `allow_from` in each
  `agent.yaml`, and the fingerprints. The agents log `ha:` lines (`journalctl -u
  portitor-agent | grep ha:`).
- **A host shows *fenced*.** It hears neither its peer nor the witness. Check both
  links and that the witness is up (portitor-web logs `witness:` lines). *stale* is an
  old primary that was taken over: wait for the new primary to catch it up.
- **Clients lose their gateway after a takeover.** The hypervisor or switch drops
  frames from the pair's MAC address on the new host: allow changed MAC addresses.
- **`DHCP leases ... not sent`** in `portitor show ha`: the active host can't reach the
  standby's agent. Clients still get leases; after a takeover they keep their
  addresses when they renew.
- **The watchdog is `softdog`.** A hung kernel isn't caught: add a hardware or emulated
  watchdog (`i6300esb` on Proxmox).
- **The secondary's copy fails** (the *HA secondary* badge shows the error): check
  the *portitor-config URL* and *fingerprint* of the primary under *Firewalls*
  (commit after setting them), and that the secondary reaches port 8444 there (the
  auto rule *portitor-config peer* on the primary).
- **A commit lists HA problems.** Each names the host and what is missing (an HA link
  or management interface, a peer address, a management gateway).
