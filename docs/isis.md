<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# IS-IS

Portitor runs IS-IS with [FRR](https://frrouting.org) (`isisd`), for IPv4 and IPv6
in one process, in every virtual firewall that turns it on. It is off until you turn
it on; FRR then starts on the next commit, and stops again when nothing else
([OSPF](ospf.md), [BGP](bgp.md), VRRP, BFD) needs it.

You set it up under *Routing → IS-IS*, in two tabs:

- **IS-IS info**: what FRR has: the system id, adjacencies, interfaces and routes.
- **IS-IS config**: what you commit.

FRR must be installed on the firewall (`apt install frr frr-pythontools`), as for
BGP.

## A first adjacency

1. *IS-IS config*: turn on *Enabled* and enter the *NET*, for example
   `49.0001.1921.6800.1001.00`: the area (`49.0001`), a system id unique to this
   router (often its loopback address, `192.168.1.1` written as `1921.6800.1001`)
   and `00`. Save.
2. Under *IS-IS interfaces*, *Add interface*: the interface towards the neighbour,
   with *IPv4*, *IPv6* or both. Turn on *Point-to-point* when there is one neighbour
   on the link. Add the interfaces whose networks you want announced too, *Passive*
   for those without IS-IS routers on them (a LAN, a loopback). Save.
3. Commit. *IS-IS info* shows the adjacency *Up* and the routes learnt.

IS-IS is not IP: its packets are layer 2 (LLC) frames on the link, so the firewall's
rules never see them, and you write no rules for it. For the same reason it can't
run over a WireGuard or 6in4 tunnel, which carry IP alone; such an interface can
only be passive, to announce its networks. Physical interfaces, VLANs, bridges,
VXLANs and the link ends between virtual firewalls all work.

## Configuration

| Field | What |
|---|---|
| NET | The network entity title: area, system id, `00`. Routers of one area share the area and have their own system id. |
| Level | *level-1* routes inside the area, *level-2-only* between areas (the backbone), *level-1-2* (FRR's default) both. |
| Metric style | *wide* (the default; metrics up to 16777215), *narrow* (up to 63, for old routers) or *transition*. |
| IPv6 topology | Multi-topology (RFC 5120): IPv6 gets a topology of its own, so a link may run IPv4 or IPv6 alone. Every router of the area must agree; needs wide metrics. |
| Log adjacency changes | Logs neighbours coming and going. |
| Overload | Sets the overload bit: the other routers stop routing through this one, for maintenance. |
| Area password | Authenticates the level-1 link-state packets (LSPs and SNPs), clear text or HMAC-MD5. The same on every router of the area. |
| Domain password | The same for level 2, on every level-2 router. |
| Default originate | Announces a default route (IPv4 or IPv6) into level 1 or 2, while the routing table has one, or with *Always* in any case; optionally with a metric and a route map. |
| Redistribute | Connected networks, static routes (*Static*), BGP's or OSPF's routes (OSPFv2's into IPv4, OSPFv3's into IPv6), each into level 1 or 2, with an optional metric and route map. |

**Interfaces** are the interfaces of the virtual firewall IS-IS runs on, link ends
between virtual firewalls included:

| Field | What |
|---|---|
| IPv4 / IPv6 | Runs IS-IS for the interface's IPv4 or IPv6 networks, or both. |
| Circuit type | Limits the levels of the adjacencies on the interface; empty: the router's level. |
| Point-to-point | Skips the DIS election, for links and tunnels with one neighbour. Both ends must agree. |
| Passive | Announces the networks but sends no hellos: no neighbours there. |
| Metric | The cost of sending through the interface; 0 keeps 10. |
| Hello interval / multiplier | Seconds between hellos (3), and how many may be missed before a neighbour is taken as gone (10). |
| Priority | In the election of the DIS on a LAN (64). |
| BFD | Detects a lost neighbour with [BFD](bfd.md), when the interface has it. |
| Hello password | Authenticates the hellos on the interface, clear text or HMAC-MD5; the neighbour needs the same. |

Passwords are never shown again once saved: leave the field empty to keep one,
*Remove* to take it away. In the committed configuration's preview and the
deployment history they read `<redacted>`.

Renaming an interface renames it here; an interface IS-IS uses can't be deleted. A
route map IS-IS uses can't be deleted either, and renaming it rewrites IS-IS's
reference ([Routing objects](bgp.md#routing-objects)).

## How it runs

IS-IS runs in the same FRR as BGP and OSPF, from the same files (`frr.conf`,
`daemons`; see [BGP](bgp.md#how-it-runs)), as the process `router isis portitor`.
Turning IS-IS on or off changes the daemons FRR runs, which restarts FRR (and resets
the other protocols' sessions); other changes are reloaded with `frr-reload.py`.

*Static* in *Redistribute* means the static routes Portitor installs: FRR's
`redistribute kernel`.

## In a VRF

Each [VRF](vrf.md) can run an IS-IS of its own, on its interfaces: choose the VRF
at the top of the page; see [VRFs](vrf.md#routing-protocols).

## With BGP and OSPF

BGP's *Redistribute* has *IPv4 IS-IS* and *IPv6 IS-IS*, and OSPF's has *IS-IS*
(IPv4 routes into OSPFv2, IPv6 into OSPFv3). IS-IS's own *Redistribute* has *BGP*
and *OSPF*. Redistributing both ways on more than one router can loop routes;
filter them with route maps.

On the firewall, as root, `vtysh` (`vtysh -N <name>` for a virtual firewall) shows
everything FRR has: `show isis neighbor`, `show isis interface`, `show isis
database`, `show isis route`.
