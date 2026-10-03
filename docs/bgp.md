<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# BGP

Portitor runs BGP with [FRR](https://frrouting.org) (its `zebra` and `bgpd`
daemons), one FRR per virtual firewall that has BGP turned on. BGP is off until you
turn it on; FRR then starts on the next deploy, and stops again when you turn BGP
off.

You set it up under *Network → Routing*:

- **Routing objects**: prefix lists, AS path lists, community lists and route maps.
  BGP filters with them, by name.
- **BGP**: the *BGP info* tab shows what FRR has (sessions, the BGP table), the
  *Configuration* tab what you deploy.

FRR must be installed on the firewall (`apt install frr frr-pythontools`; the
installer ISO does). Without `frr-pythontools` (FRR's `frr-reload.py`) a changed
configuration restarts FRR, which resets the sessions, instead of reloading it.
The Dashboard lists it under missing programs while a virtual firewall with BGP on
lacks it.

## A first session

1. *Network → Routing → BGP*, *Configuration*: turn on *Enabled*, enter the *Local
   AS* (`65000`) and, optionally, a *Router id* (an IPv4 address of the firewall;
   empty, FRR picks one). Save.
2. Under *Neighbours*, *New neighbour*: the neighbour's address and *Remote AS*. Keep
   *IPv4 unicast → Activate* on (turn on *IPv6 unicast* too for IPv6 routes, over the
   same session or one to the neighbour's IPv6 address). Save.
3. Add what you announce: a *Network* for each prefix of yours, or *Redistribute*
   connected networks or static routes.
4. Deploy. *BGP info* shows the session coming up (Established) and the routes.

The firewall opens TCP port 179 to and from its neighbours by itself (an *auto*
rule, as for DHCP and DNS); you write no rules for the sessions. A neighbour that is
shut down gets none.

## Configuration

**BGP** holds what applies to all neighbours:

| Field | What |
|---|---|
| Local AS | The firewall's AS number (1-4294967295). |
| Router id | An IPv4 address that names the router; empty, FRR picks one. |
| Keepalive / hold | The default timers in seconds; 0 keeps BGP's 60 / 180. |
| eBGP requires policy | RFC 8212: off by default here. On, an eBGP neighbour exchanges routes only with a route map in and out. |
| Graceful restart, Multipath relax, Maximum paths | Restart without dropping routes; load sharing over paths through different ASes, over at most this many paths. |
| Networks | Prefixes announced while the routing table has them (a connected network, a static route), each with an optional route map. |
| Aggregate addresses | A shorter prefix announced while a more specific route is in the BGP table. *Summary only* leaves the more specific ones out; *AS set* keeps their ASes in the path. |
| Redistribute | For IPv4 and IPv6: connected networks (the interfaces' prefixes) and static routes (*Static routes*), each with an optional route map that filters or changes them. |

**Peer groups** are settings shared by several neighbours. A neighbour in a group
takes the group's settings; what the neighbour sets adds to them. Renaming a group
renames it in its neighbours; one with neighbours can't be deleted.

**Neighbours** have, besides the address and remote AS:

| Field | What |
|---|---|
| Remote AS | An AS number, `internal` (the local AS: iBGP) or `external` (any other). May be left empty in a peer group that has one. |
| Password | TCP MD5 signature; never shown again once saved. Leave it empty to keep it, *Remove* to take it away. |
| eBGP multihop | For an eBGP neighbour that is not directly connected, with the TTL (255 by default). |
| Update source | The interface or address the session comes from (peering between loopbacks). |
| Passive, Shut down | Wait for the neighbour to connect; keep the session down. |
| Activate | Exchange routes of this address family (IPv4 unicast, IPv6 unicast). |
| Filter in / out | No filter, a prefix list (of the family's IP version) or a route map, in each direction. |
| Next hop self | Announce the firewall as the next hop (iBGP, towards routers that can't reach the eBGP neighbour). |
| Remove private AS | Leave private AS numbers out of the path sent (eBGP only). |
| Soft reconfiguration | Keep the routes received before the filter, so a changed filter applies without resetting the session. |
| Default originate | Send the neighbour a default route. |
| Route reflector client | Reflect iBGP routes to this neighbour (iBGP only). |
| Allow own AS in, Maximum prefixes | Accept routes with the local AS in their path (so many times); shut the session down when the neighbour sends more prefixes. |

FRR always offers route refresh to its neighbours; it is not a setting.

## Routing objects

Objects belong to their virtual firewall. Renaming one rewrites everything that uses
it; one in use can't be deleted (the message names what uses it). An object with no
entries matches nothing.

- **Prefix lists** (IPv4 or IPv6) match prefixes: `10.0.0.0/8` matches exactly that
  prefix; with *ge* and *le*, the prefixes inside it of those lengths
  (`10.0.0.0/8 le 24`: /8 to /24); `any` matches every prefix. Entries are tried in
  sequence order (a new entry gets the next multiple of 5); the first that matches
  permits or denies, and what none matches is denied.
- **AS path lists** match the AS path with regular expressions, tried in order: `_`
  matches a space or the start or end of the path, so `_65001_` is a path through AS
  65001, `^65001_` one received from it, `_65001$` one that started in it, and `^$`
  a route of the local AS.
- **Community lists**: *standard* entries match routes that carry all the
  communities listed (`65000:100`, or well-known ones: `no-export`, `no-advertise`,
  `local-AS`, `blackhole`, `graceful-shutdown`, ...); *expanded* entries match the
  communities as text with a regular expression. The large kinds do the same for
  large communities (`65000:1:2`).
- **Route maps** are a list of entries, tried in sequence order. The first entry
  whose matches all match permits the route (and sets what it sets: local
  preference, MED, weight, AS path prepend, communities, next hop, origin) or denies
  it. *On match next* goes on to the next entry after a permit instead of stopping.
  A route that no entry matches is denied, so end a route map that should let the
  rest through with a permit entry that matches anything.

## How it runs

The default virtual firewall (the host) runs the distribution's `frr.service` from
`/etc/frr` (`frr.conf`, `daemons`, `vtysh.conf`; files that were there before are
kept as `*.portitor-orig`). Every other virtual firewall runs
`portitor-frr@<name>.service` in its network namespace, with its files in
`/etc/portitor/instances/<name>/frr`, mounted as FRR's *pathspace*
`/etc/frr/<name>`. Its daemons keep the capability CAP_SYS_ADMIN, which FRR needs to
start, where the other daemons of a virtual firewall drop it.

A changed configuration is applied with FRR's `frr-reload.py`, which keeps the
sessions up; a change to the daemons FRR runs, or a reload that fails, restarts it.

*Static* in *Redistribute* means the static routes Portitor installs (in the kernel
routing table, so FRR sees them as kernel routes): FRR's `redistribute kernel`.

On the firewall, as root, `vtysh` (`vtysh -N <name>` for a virtual firewall) shows
everything FRR has: `show bgp summary`, `show bgp neighbors`, `show bgp ipv4
unicast`. *BGP info* leaves out the BGP table of an address family with more than
2000 routes (a full Internet table); vtysh shows it.
