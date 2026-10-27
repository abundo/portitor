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
  vote of a third party, the **witness**. A host that hears neither
  **fences** itself, so two hosts that can't see each other never both answer for the
  same addresses.
- **State follows.** DHCP leases (Kea's HA), open connections (conntrackd) and ACME
  certificates are kept on both, so a takeover doesn't drop clients.
- **The configuration survives.** portitor-config on the primary holds the pair's
  configuration; the secondary's keeps a read-only copy, and can be **promoted** when
  the primary is lost.

## What you need

- **Two firewalls with the same interface names** (`ens18`, `ens19`, ...). The
  secondary runs the primary's interfaces by name.
- **portitor-agent and portitor-config on both** (`install.py --agent HOST` installs
  both).
- **A witness.** By default it is portitor-config on the primary, which keeps the pair
  safe when the two can't hear each other but goes with the primary: lose the primary
  and the secondary fences instead of taking over, until you
  [promote](#promoting-the-secondary) it. For a takeover by itself, run an **external
  witness** on a third host (see [The witness](#the-witness)), usually the portal
  ([HA pair and portal](deployments.md#ha-pair-and-portal)).
- **The agents reachable from each other** (and from an external witness). In each
  `/etc/portitor/agent.yaml`, `listen` on an address the others reach (`":8443"`), and
  `allow_from` including the peer's (and the witness's) addresses (loopback, for its
  own portitor-config, is always allowed). Then `systemctl restart portitor-agent`.
- **The secondary's portitor-config able to reach the primary's** (port 8444), to copy
  the configuration, and the other way round once it is promoted. With each host's
  *portitor-config URL* set under *Firewalls*, an auto rule (*portitor-config peer*)
  opens that port to the peer's addresses in its agent and portitor-config URLs
  (written as addresses, not names).
- **The agents' certificate fingerprints.** The hosts pin each other's certificates:
  `openssl x509 -in /etc/portitor/agent.crt -noout -fingerprint -sha256` on each.
- **conntrackd** on both (`install.py` installs it; on an offline host,
  `apt install conntrackd`).

## Setting up a pair

Everything is done in the primary's portitor-config.

1. **The primary** is the firewall under *Admin → Firewalls*. Set its agent URL to
   its address on the network, which the secondary uses (`https://192.0.2.5:8443`),
   not `127.0.0.1`: each portitor-config reaches its own agent at the `agent_url` in
   its `config.yaml`, and the other host's at the address here. Set its
   *portitor-config URL* (`https://192.0.2.5:8444`) and *fingerprint*
   (`portitor-config fingerprint` on it), for the secondary to copy from.
2. **The secondary**: *New firewall*, with its agent URL, token and fingerprint
   (`portitor-agent init` there prints them), its *portitor-config URL* and
   *fingerprint*, and *HA secondary of* the primary. This can only be chosen when the
   firewall is created. The secondary has no virtual firewalls of its own: it runs
   the primary's.
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
4. **The shared addresses** are VRRP's: a VRRP on each LAN, with the
   gateway address the clients use (*Routing → VRRP*). Turn on *Preempt* if the
   primary should take the address back when it returns.
5. **Commit.** Both hosts get the configuration; confirm it as usual.

*Admin → Firewalls* then shows each host's role in the *HA* column: *peer alive*,
*peer gone, witness vote*, or *fenced*.

From that commit on, the secondary's agent knows it is the secondary, and its
portitor-config becomes a **replica**: it copies the primary's database every
15 seconds (when it changed; `GET /ha/v1/database` on the primary, with the pair's
secret), users included, and refuses changes. Its GUI shows an *HA secondary* badge
with the last copy. Log in there with the primary's users.

## Quorum and fencing

Each host sends a heartbeat to its peer every second, and counts it as gone after
3 seconds without an answer. The witness asks both hosts every 2 seconds and gives
its **vote** to one of them for 10 seconds at a time, renewing it while it sees that
host.

A host has a **quorum**, and may be active, while it hears its peer **or** holds the
witness's vote. Without either it is **fenced**: its VRRP routers are shut down and it
serves no DHCP or router advertisements, so it can't answer for the shared addresses.
It lifts the fence by itself as soon as it hears its peer or gets the vote again.

| What fails | What happens |
|---|---|
| The primary (host down, or cut off) | With an external witness: the secondary loses its peer, gets the witness's vote (at once if it held it, else when the primary's vote runs out), and its VRRP takes the addresses over. The primary, if it is still running but cut off, fences itself. With the primary's portitor-config as witness, the secondary fences: [promote](#promoting-the-secondary) it. |
| The link between the two | Each still sees the witness, which votes for one of them only: that one stays active, the other fences. |
| The witness | Nothing changes while the two hear each other. |
| Both the peer and the witness, from one host | That host fences: it can't tell whether the other took over. |

The vote moves only when its holder can't be asked and its vote has run out, so it
never flips between the hosts. After the witness restarts, it learns the holder from
the hosts.

A host that restarts (an update, a reboot) starts fenced, unless its peer answers at
once. It then joins without moving the addresses.

## What the pair keeps in step

| | How |
|---|---|
| **Configuration** | Kept by the primary's portitor-config, copied by the secondary's. Every commit goes to both hosts. If one can't be reached and the other can, the commit goes to the reachable one, and the other is shown as *skipped*: it gets the commit as soon as it answers again. If neither can be reached, there is no commit. |
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
portitor show vrrp                        # master or backup, per VRRP
```

**When neither the peer nor the witness can be reached** (the witness down, or the
primary's portitor-config, and the other host down too), the remaining host stays
fenced. If you *know* the other host is
down, you can let this one be active by hand:

```
portitor request ha active --minutes 60
```

This is logged. Never do it while the other host may still be running: both would
answer for the same addresses.

## The witness

A pair has one witness, never two: two could each vote for another host, and both
would be active.

- **The primary's portitor-config** (*HA witness*: *This firewall's portitor-config*,
  the default). Nothing else to run. It keeps the pair from a split brain when the
  link between them fails, but a lost primary takes the witness with it: the
  secondary fences until it is promoted.
- **External** (*HA witness*: *External*): portitor-web on a third host, which may be
  the portal or not. Set it on the primary under *Admin → Firewalls*, commit, and copy
  the *Witness string* (or `portitor-config witness-string` on the primary's console)
  into `/etc/portitor/web.yaml` on the third host:

  ```yaml
  witness:
    - portitor-witness:eyJwYWlyIjoi...
  ```

  `portitor-web start` (the portal) is then the witness too; `portitor-web witness`
  is the witness alone, without the GUI. The string holds both agents' URLs (their *HA
  URL*, else agent URL) and certificate fingerprints, and the pair's witness secret,
  which opens nothing on the agents but the quorum and the vote. The agents must let
  the third host in (`allow_from`).

## Promoting the secondary

When the primary is lost (dead hardware, a site gone), promote the secondary: its
copy of the configuration becomes the pair's.

- In the secondary's GUI: the *HA secondary* badge in the top bar, then *Promote* (a
  global admin). Or on its console: `sudo -u portitor portitor-config promote`.
- It is refused while the secondary's agent hears the primary: promote only a
  secondary whose primary is gone. `--force` (or *Force* in the GUI) promotes anyway;
  then both believe they own the configuration until the old primary is caught up.

The promotion swaps the two hosts in the configuration: the virtual firewalls and
tasks move to the secondary, with the two hosts' values swapped (addresses and *HA
peer addresses*, router ids, NETs, BGP neighbours' *HA peer address*, VRRP priority
and *HA peer priority* where both are set), the old primary becomes the secondary,
the pair's **epoch** goes up, and it commits. The commit skips the old primary while
it is away.

When the old primary comes back, its agent still has the document of before. It
hears its peer answer as primary at a higher epoch: it has been taken over, so it
stays **fenced** (and refuses documents of the earlier epoch). Its portitor-config
becomes a replica of the new primary. The new primary then catches it up with the
secondary's configuration, and it takes part as the secondary. To drop it instead,
delete it under *Admin → Firewalls* and add a new secondary later.

Lost with the primary: changes made there since the secondary's last copy, and the
*Revert* snapshots (Revert works again after the next commit).

## Troubleshooting

- **Both hosts show *peer: not heard*.** The heartbeat goes to the agent URL (or *HA
  URL*) of the other: check `listen` and `allow_from` in each `agent.yaml`, and that
  the fingerprints are right. The agents log `ha:` lines (`journalctl -u
  portitor-agent | grep ha:`).
- **A host stays fenced** although the other is fine: it hears neither. Check the
  network between them, and that the witness is up (portitor-config on the primary,
  or portitor-web: both log `witness:` lines). `portitor show ha` says *stale* on an
  old primary that was taken over: wait for the new primary to catch it up.
- **The secondary's copy fails** (the *HA secondary* badge shows the error): check
  the *portitor-config URL* and *fingerprint* of the primary under *Firewalls*
  (commit after setting them), and that the secondary reaches port 8444 there (the
  auto rule *portitor-config peer* on the primary).
- **Both are VRRP master.** Their VRRP advertisements don't reach each other (a
  firewall rule, or a switch between them). Fencing only acts when a host loses its
  quorum.
- **A commit lists HA problems.** Each names the host and what is missing (an HA peer
  address, router id, NET, or an agent URL the peer can't reach).
