<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# OSPF

Portitor runs OSPF with [FRR](https://frrouting.org): **OSPFv2** (IPv4, FRR's
`ospfd`) and **OSPFv3** (IPv6, `ospf6d`), each on its own, in every virtual firewall
that turns it on. Both are off until you turn them on; FRR then starts on the next
commit, and stops again when neither OSPF nor [BGP](bgp.md) is on.

You set it up under *Network → Routing → OSPF*, in four tabs:

- **OSPFv2 info** and **OSPFv3 info**: what FRR has: the router id, neighbours,
  interfaces, areas and routes.
- **OSPFv2 config** and **OSPFv3 config**: what you commit.

FRR must be installed on the firewall (`apt install frr frr-pythontools`), as for
BGP.

## A first adjacency

1. *OSPFv2 config*: turn on *Enabled* and, optionally, enter a *Router id* (an IPv4
   address of the firewall; empty, FRR picks one). Save.
2. Under *OSPFv2 interfaces*, *Add interface*: the interface towards the neighbour
   router, in area `0.0.0.0` (the backbone). Add the interfaces whose networks you
   want announced too, and turn on *Passive* for those without OSPF routers on them
   (a LAN): their networks are announced, but no hellos are sent there. Save.
3. Commit. *OSPFv2 info* shows the neighbour reaching *Full* and the routes learnt.

OSPFv3 is the same, under its own tabs, for the interfaces' IPv6 networks. Its
router id is an IPv4 address too; with none set, FRR takes one of the firewall's
IPv4 addresses, so set one on a firewall with IPv6 only.

The firewall lets OSPF in and out on the interfaces OSPF runs on by itself (*auto*
rules for IP protocol 89, as for DHCP and DNS); you write no rules for it. A passive
interface gets none.

## Configuration

| Field | What |
|---|---|
| Router id | An IPv4 address that names the router; empty, FRR picks one. Each router of the OSPF domain needs its own. |
| Reference bandwidth | The bandwidth, in Mbit/s, of cost 1; an interface's cost is this divided by its speed. 0 keeps 100 Mbit/s, which makes every link of 100 Mbit/s or more cost 1. Use the same on every router. |
| Log adjacency changes | Logs neighbours coming and going. |
| Maximum paths | Equal-cost paths installed; 0 keeps FRR's default. |
| Default originate | Announces a default route while the routing table has one, or with *Always* in any case. |
| Area types | An area is normal unless listed here. A *stub* area gets no external routes, a default route instead; an *NSSA* may have external routes of its own. *No summary* also keeps the other areas' routes out (totally stubby). The backbone (`0.0.0.0`) is always normal. |
| Networks (OSPFv2) | Runs OSPF on the interfaces with an address in the prefix, in its area: the other way to enable OSPFv2 than an interface's area. FRR does not allow both: with network statements, leave the interfaces' areas empty and list an interface only to set its options. |
| Area ranges | On a router in more than one area: the area's networks inside the prefix are announced to the other areas as the prefix alone (with the cost given, or the highest inside), or not at all. |
| External summaries | Redistributed routes inside the prefix are announced as the prefix alone, or not at all. |
| Redistribute | Connected networks, static routes (*Static routes*) and BGP's routes, announced as external routes, each with an optional route map, a metric (its cost; empty: 20) and a metric type (type 2 keeps the metric as it is; type 1 adds the cost of the way to this router). |

Area ids are written dotted (`0.0.0.1`); a number (`1`) is turned into that form.

**Interfaces** are the interfaces of the virtual firewall OSPF runs on, link ends
between virtual firewalls included:

| Field | What |
|---|---|
| Area | The area of the interface's networks (all its IPv4 networks for OSPFv2, IPv6 for OSPFv3). |
| Passive | Announces the networks but sends no hellos: no neighbours there. |
| Cost | The cost of sending through the interface; 0 follows from the reference bandwidth. |
| Hello / dead interval | Seconds between hellos (10), and without them before a neighbour is taken as gone (40). They must match on both ends. |
| Priority | In the election of the designated router on a broadcast network (1); 0 never becomes DR. |
| Network type | *point-to-point* skips the DR election, for links and tunnels with one neighbour (a WireGuard tunnel, which also needs it); empty keeps the interface's. |
| MD5 key (OSPFv2) | Authenticates the packets with a key (up to 16 characters) and key id, which must match on the neighbour's side. Never shown again once saved: leave it empty to keep it, *Remove* to take it away. |

Renaming an interface renames it here; an interface OSPF uses can't be deleted. A
route map OSPF uses can't be deleted either, and renaming it rewrites OSPF's
reference ([Routing objects](bgp.md#routing-objects)).

## With BGP

BGP's *Redistribute* has *IPv4 OSPF* and *IPv6 OSPF*: OSPFv2's routes into IPv4,
OSPFv3's into IPv6. OSPF's *Redistribute* has *BGP*. Redistributing both ways on
more than one router can loop routes; filter them with route maps.

## How it runs

OSPF runs in the same FRR as BGP, from the same files (`frr.conf`, `daemons`; see
[BGP](bgp.md#how-it-runs)). Turning OSPFv2 or OSPFv3 on or off changes the daemons
FRR runs, which restarts FRR (and resets the BGP sessions); other changes are
reloaded with `frr-reload.py`, which keeps the adjacencies up.

*Static* in *Redistribute* means the static routes Portitor installs: FRR's
`redistribute kernel`.

On the firewall, as root, `vtysh` (`vtysh -N <name>` for a virtual firewall) shows
everything FRR has: `show ip ospf neighbor`, `show ip ospf interface`, `show ip ospf
database`, `show ip ospf route`, and for OSPFv3 the same with `show ipv6 ospf6`.
