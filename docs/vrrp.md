<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# VRRP

VRRP (Virtual Router Redundancy Protocol) lets two or more routers on the same
network share a gateway address. One router, the **master**, holds the address and
answers for it. The others are **backups**: when the master stops sending
advertisements, the backup with the highest priority takes the address over, within
about three advertisement intervals. The hosts keep the same gateway the whole time,
because the address and its MAC address move together.

Portitor runs VRRP with [FRR](https://frrouting.org)'s `vrrpd`, in every virtual
firewall that has a virtual router. It supports **VRRPv3** (RFC 5798, IPv4 and IPv6)
and **VRRPv2** (RFC 3768, IPv4 only). FRR starts with the first virtual router at the
next commit, and stops when there are no virtual routers and neither [BGP](bgp.md)
nor [OSPF](ospf.md) is on.

You set it up under *Network → Routing → VRRP*, in two tabs:

- **Virtual routers**: what you commit.
- **VRRP info**: what FRR has: master or backup, per virtual router and IP version.

FRR must be installed on the firewall (`apt install frr frr-pythontools`), as for
BGP.

## A gateway shared by two firewalls

Two firewalls, `fw1` and `fw2`, are both on the LAN `192.168.1.0/24`, on their
interface `lan` with the addresses `192.168.1.2/24` and `192.168.1.3/24`. The hosts
should use `192.168.1.1` as their gateway.

1. On `fw1`, *New virtual router*: interface `lan`, *Virtual router id* `1`, *IPv4
   addresses* `192.168.1.1`, *Priority* `200`. Save and commit.
2. On `fw2`, the same, with *Priority* `100`. Save and commit.
3. *VRRP info* shows `fw1` as *Master* and `fw2` as *Backup*.
4. Give the hosts `192.168.1.1` as their gateway. With the DHCP server (*Services →
   DHCP*), set the prefix's *Gateway* to it on both firewalls; otherwise each firewall
   hands out its own address.

When `fw1` goes down, `fw2` becomes master within about three seconds (with the
default interval). When `fw1` comes back, it takes over again, as its priority is
higher, unless *Preempt* is off.

The virtual router id must be the same on every router of the group, and must not be
used by another group on the same network: it is part of the virtual MAC address
(`00:00:5e:00:01:<id>` for IPv4, `00:00:5e:00:02:<id>` for IPv6).

## Configuration

| Field | What |
|---|---|
| Interface | The interface (or link end) the virtual router is on: a physical interface, VLAN, bridge or link end. |
| Virtual router id | 1-255, the same on every router of the group. An interface can have several virtual routers, with different ids. |
| IPv4 addresses | The virtual addresses, in a network of the interface (one of its static addresses' prefixes), and none of the firewall's own addresses. |
| IPv6 addresses | The same for IPv6 (VRRPv3 only): a link-local address (`fe80::1`) or one in a network of the interface. |
| Version | VRRPv3 (the default) or VRRPv2, for routers that only speak VRRPv2. VRRPv2 is IPv4 only. All routers of the group must use the same version. |
| Priority | 1-254 (default 100). The router with the highest priority is master; on a tie, the one with the highest interface address. |
| Advertisement interval | How often the master sends an advertisement, in milliseconds (default 1000): 10-40950, a multiple of 10; VRRPv2 takes whole seconds. The same on every router of the group. |
| Preempt | A router of higher priority takes over from the master (on by default). Off, the master keeps the address until it fails. |
| Enabled | Off, the virtual router is shut down: configured, but never master. |

A virtual router with both IPv4 and IPv6 addresses is two virtual routers in VRRP,
one per IP version, with the same id; each elects its own master.

## How it works on the firewall

Each virtual router of each IP version gets a macvlan device on its interface, named
`vrrp4-<id>-<interface>` or `vrrp6-<id>-<interface>` (with a hash in place of a long
interface name), with the virtual MAC address and the virtual addresses. FRR turns
the device on while the firewall is master, and off (*protodown*) while it is
backup. A new device starts off, so a firewall never answers for the address before
FRR has decided it is master. Interface names starting with `vrrp4-` or `vrrp6-` are
reserved for these devices.

What the hosts send to the gateway arrives on the device, not on the interface.
Rules, NAT rules and the auto rules that name the interface (or an interface zone
with it) match on its VRRP devices too, so you write the rules for the interface as
before.

The firewall lets VRRP advertisements (IP protocol 112) in and out on the interfaces
with virtual routers by itself (*auto* rules); you write no rules for them.

An interface with an IPv4 virtual router answers ARP only for its own addresses
(`arp_ignore` 1), so the virtual addresses are answered by their devices, with the
virtual MAC address, and never by a backup's interface.

## Limits

- **Services on the virtual address.** The DNS server listens on the interfaces'
  own addresses; the hosts reach it there, not on the virtual address. Give the hosts
  the firewalls' own addresses as DNS servers.
- **DHCP on both firewalls.** Two DHCP servers on the same network hand out
  addresses from the same range without knowing of each other. Run the DHCP server on
  one of them, or give each a range of its own.
- **IPv6 router advertisements** name the interface's own link-local address as the
  router, not the virtual one. Hosts learn every router that sends advertisements,
  and stop using one that disappears, which is IPv6's own redundancy; the virtual
  IPv6 address helps hosts configured with a static gateway.
- **The firewall's state** (connection tracking, NAT) is not shared between the
  routers: connections through the master are cut when the backup takes over, and
  are made again.
