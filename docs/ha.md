<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# High availability (HA pairs)

Two firewalls can run as an **HA pair**: a **primary** and a **secondary** with the
same virtual firewalls, rules, routing and services. Both run the configuration all
the time. [VRRP](vrrp.md) decides which of them answers for the shared gateway
addresses; when the master fails, the other takes over within seconds, and the
clients keep their gateway.

Around that, Portitor keeps the pair in step and safe:

- **Every commit goes to both.** A change is applied to the two hosts together, waits
  for confirmation on both, and is rolled back on both if either fails.
- **No split brain.** A host may only be active while it hears its peer, or holds the
  vote of a third party, the **witness** (portitor-web). A host that hears neither
  **fences** itself, so two hosts that can't see each other never both answer for the
  same addresses.
- **State follows.** DHCP leases (Kea's HA), open connections (conntrackd) and ACME
  certificates are kept on both, so a takeover doesn't drop clients.

## What you need

- **Two firewalls with the same interface names** (`ens18`, `ens19`, ...). The
  secondary runs the primary's interfaces by name.
- **A third host for portitor-web**, the witness. If portitor-web runs on one of the
  pair, losing that host leaves the other without a quorum, and it fences instead of
  taking over (see [Quorum and fencing](#quorum-and-fencing)).
- **The agents reachable from each other and from portitor-web.** In each
  `/etc/portitor/agent.yaml`, `listen` on an address the others reach (`":8443"`), and
  `allow_from` including the peer's and portitor-web's addresses. Then
  `systemctl restart portitor-agent`.
- **The agents' certificate fingerprints.** The hosts pin each other's certificates:
  `openssl x509 -in /etc/portitor/agent.crt -noout -fingerprint -sha256` on each.
- **conntrackd** on both (`install.py` installs it; on an offline host,
  `apt install conntrackd`).

## Setting up a pair

1. **The primary** is an ordinary firewall under *Admin → Firewalls*, with its agent
   URL, token and fingerprint. If portitor-web reaches its agent at another address
   than the secondary will (portitor-web on the same host uses `127.0.0.1`, say), set
   its *HA URL* to the address the secondary uses: `https://192.0.2.5:8443`.
2. **The secondary**: *New firewall*, with its own agent URL, token and fingerprint,
   and *HA secondary of* the primary. This can only be chosen when the firewall is
   created. The secondary has no virtual firewalls of its own: it runs the primary's.
3. **Its own addresses.** Some values must differ between the two hosts. Where a pair
   uses them, the forms show an *HA peer* field for the secondary's value:

   | Where | Field | The secondary's |
   |---|---|---|
   | *Network → Interfaces* | *HA peer addresses* | own address for each static address, in the same prefix and order. A loopback's /32 or /128 may be any other one. Delegated addresses (`<wan0>:…`) are each host's own and need none. |
   | *Routing → VRRP* | *HA peer priority* | priority. Empty: 10 below the primary's, so the primary is master. |
   | *Routing → BGP*, *OSPF* | *HA peer router id* | router id, where one is set. |
   | *Routing → IS-IS* | *HA peer NET* | NET, where it is entered (one made from an interface follows its peer address). |
   | *Routing → BGP*, a neighbour | *HA peer address* | neighbour's address, for a neighbour on the pair itself (another virtual firewall, over a link). |

   A commit lists what is missing (`fw2: main: interface lan: the HA secondary needs an
   address of its own ...`).
4. **The shared addresses** are VRRP's: a virtual router on each LAN, with the
   gateway address the clients use (*Routing → VRRP*). Turn on *Preempt* if the
   primary should take the address back when it returns.
5. **Commit.** Both hosts get the configuration; confirm it as usual.

*Admin → Firewalls* then shows each host's role in the *HA* column: *peer alive*,
*peer gone, witness vote*, or *fenced*.

## Quorum and fencing

Each host sends a heartbeat to its peer every second, and counts it as gone after
3 seconds without an answer. portitor-web, the witness, asks both hosts every
2 seconds and gives its **vote** to one of them for 10 seconds at a time, renewing it
while it sees that host.

A host has a **quorum**, and may be active, while it hears its peer **or** holds the
witness's vote. Without either it is **fenced**: its VRRP routers are shut down and it
serves no DHCP or router advertisements, so it can't answer for the shared addresses.
It lifts the fence by itself as soon as it hears its peer or gets the vote again.

| What fails | What happens |
|---|---|
| The primary (host down, or cut off) | The secondary loses its peer, gets the witness's vote (at once if it held it, else when the primary's vote runs out), and its VRRP takes the addresses over. The primary, if it is still running but cut off, fences itself. |
| The link between the two | Each still sees the witness, which votes for one of them only: that one stays active, the other fences. |
| portitor-web (the witness) | Nothing changes while the two hear each other. |
| Both the peer and the witness, from one host | That host fences: it can't tell whether the other took over. |

The vote moves only when its holder can't be asked and its vote has run out, so it
never flips between the hosts. After portitor-web restarts, it learns the holder from
the hosts.

A host that restarts (an update, a reboot) starts fenced, unless its peer answers at
once. It then joins without moving the addresses.

## What the pair keeps in step

| | How |
|---|---|
| **Configuration** | Every commit goes to both hosts. If one can't be reached and the other can, the commit goes to the reachable one, and the other is shown as *skipped*: it gets the commit as soon as it answers again. If neither can be reached, there is no commit. |
| **DHCP** | Kea's HA hook in hot-standby: the primary serves and keeps the standby's leases in step; the standby serves when the primary stops answering. |
| **Connections** | conntrackd sends each host's connections to the other, which keeps them in its own table, so connections through the firewall live on after a takeover. Connections to the firewall itself (SSH to it, say) end there. |
| **ACME certificates** | The active host orders and renews them; the other copies them every minute, so it has them when it takes over. |
| **DNS updates, tunnel broker** | Only on the active host (the primary, or the secondary once it no longer hears the primary), so the two never publish their own addresses in turn. |

Kea and conntrackd talk over one interface per virtual firewall: its DHCP interface,
or else its first physical interface (or VLAN on one) with a static IPv4 address and an
HA peer address. Only the peer may reach them there (auto rules *dhcp ha* and
*conntrack sync*). A virtual firewall with only internal links (to other virtual
firewalls) syncs nothing: there is nothing to reach the other host over.

## On the console

On either host, as root:

```
portitor show ha                          # node, peer, witness vote, fenced or not
portitor show vrrp                        # master or backup, per virtual router
```

**When neither the peer nor the witness can be reached** (portitor-web down, and the
other host down too), the remaining host stays fenced. If you *know* the other host is
down, you can let this one be active by hand:

```
portitor request ha active --minutes 60
```

This is logged. Never do it while the other host may still be running: both would
answer for the same addresses.

## With portitor-config

If the pair is managed through portitor-config (see
[portitor-config](portitor-web.md#portitor-config-a-firewalls-own-configuration)),
portitor-config on the primary holds the pair's configuration and deploys to both
hosts. The manager (portitor-web on a third host) stays the witness: portitor-config
doesn't vote when it has a manager, since two witnesses could each vote for another
host.

## Troubleshooting

- **Both hosts show *peer: not heard*.** The heartbeat goes to the agent URL (or *HA
  URL*) of the other: check `listen` and `allow_from` in each `agent.yaml`, and that
  the fingerprints are right. The agents log `ha:` lines (`journalctl -u
  portitor-agent | grep ha:`).
- **A host stays fenced** although the other is fine: it hears neither. Check the
  network between them, and that portitor-web is up (it logs `witness:` lines).
- **Both are VRRP master.** Their VRRP advertisements don't reach each other (a
  firewall rule, or a switch between them). Fencing only acts when a host loses its
  quorum.
- **A commit lists HA problems.** Each names the host and what is missing (an HA peer
  address, router id, NET, or an agent URL the peer can't reach).
