<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# VRFs

A **VRF** (virtual routing and forwarding) gives some interfaces of a virtual
firewall a routing table of their own. Traffic that comes in on them is routed
by that table only, apart from the rest of the virtual firewall, so two VRFs can
have their own default routes and overlapping networks.

Each virtual firewall has its own VRFs:
two virtual firewalls can each have a VRF called `blue` with table 10, and they
have nothing to do with each other.

A VRF and a virtual firewall solve different problems. A VRF keeps routing
apart but shares everything else: the rules, NAT, the connection table and the
firewall's own services. A virtual firewall keeps all of it apart.

## Settings

VRFs are made under *Routing → VRF*, *New VRF*:

- **Name**: such as `blue`. A Linux `vrf` device of that name is made in the
  virtual firewall, so it is at most 15 characters and not the name of an
  interface or interface zone. Renaming a VRF keeps its interfaces in it.
- **Table**: its routing table, 1 to 6399 (not 253 to 255, the kernel's own
  tables), unique in the virtual firewall.

A virtual firewall can have up to 127 VRFs.

An interface is put in a VRF under *Network → Interfaces*, with its **VRF**
field; *—* is the main table. Changing the field moves the interface to another
VRF, or back to the main table. Any kind of interface can be in a VRF, but a
bridge's member goes with its bridge: put the bridge in the VRF. A VRF that
interfaces, routes, BGP neighbours or peer groups are in, or that runs BGP, OSPF
or IS-IS, can't be deleted.

The interfaces keep their addresses, DHCP client and router advertisements: a
DHCP default route and the routes learned from router advertisements go in the
VRF's table.

## Choosing the VRF on a page

The pages that show or configure routing have a **VRF** list at the top once the
virtual firewall has a VRF: *Routing → Tables*, *BGP*, *OSPF* and *IS-IS* show
the main table's or one VRF's. The choice stays as you go from page to page.
*Neighbours* and *Connections* offer *All VRFs* too, and show a VRF column.

## Routes

A static route (*Routing → Static*) goes in a VRF's table when its **VRF**
names the VRF, or when its interface is in one. A route in a VRF to an
interface outside it sends traffic out of the VRF (route leaking).

A WireGuard site peer's networks and a 6in4 tunnel's default route go in the
table of their interface's VRF.

A static route with **BFD** may be in a VRF too, when its gateway is reached
through an interface of the same VRF.

## Routing protocols

BGP, OSPF (v2 and v3) and IS-IS run in each VRF on their own, besides the main
table's: choose the VRF at the top of their page, and configure and turn them
on there as you would the main table's. This is what PE–CE routing needs: the
customer's routes, learned from their router in the VRF, stay in the VRF's
table.

- **BGP**: each VRF has its own BGP settings (local AS, router id,
  networks, redistribution), peer groups and neighbours. A neighbour's
  interface and update source must be in its VRF, and its peer group of the
  same VRF; the same address may be a neighbour in two VRFs. EVPN sessions
  are the main table's; a VRF joins EVPN with an L3VNI (below). FRR: `router bgp <AS> vrf <name>`.
- **OSPF** and **IS-IS**: each VRF has its own settings, and runs on the
  interfaces of the VRF (the interface lists show those only). An interface
  moved to another VRF takes its OSPF and IS-IS settings to that VRF's.
  FRR: `router ospf vrf <name>`, `router ospf6 vrf <name>`, `router isis
  portitor vrf <name>`.
- **Redistribute** in a VRF takes that VRF's connected networks, static routes
  and other protocols' routes.
- **BFD** works for the protocols of a VRF as for the main table's, on the
  interfaces with BFD (*Routing → BFD*). The BFD info shows each session's VRF.
- **VRRP** works on an interface in a VRF: the VRRP's device is put in
  the same VRF, so the virtual address answers there.

The routing objects (prefix lists, route maps and so on) are shared by all.

## L3VPN over EVPN/VXLAN

A VRF with an **L3VNI** (in its settings) is an L3VPN: its routes are sent to
other VTEPs over the main table's EVPN sessions as type 5 routes, and theirs come
into its table, reached through VXLAN. See
[VXLAN and EVPN](vxlan.md#l3vpn-layer-3-vnis).

## Rules

Rules and interface zones name the interfaces in a VRF like any other. For a
packet that comes in on one, Linux gives the VRF device as the input interface
in the input and forward chains, and the interface itself as `meta sdifname`;
the firewall therefore matches those interfaces by `meta sdifname` there. A rule
whose incoming interfaces are some in VRFs and some not is rendered as two rules,
one for each kind, so it matches the same as one rule would. A VRRP device is
matched with its interface.

Outgoing interfaces need nothing special: a packet routed by a VRF's table
leaves by the interface itself, which is what `oifname` sees. What the firewall
itself sends from a socket bound to a VRF passes the output chain twice, first
with the VRF device as its output interface (let through, untracked) and then
with the interface it leaves by, where the rules decide.

NAT matches the interfaces by name in prerouting and postrouting, where a packet
from a VRF's interface still has that interface.

## Connections

The VRFs of a virtual firewall share its connection tracking table. Each new
connection that comes in on a VRF's interfaces, or that the firewall opens out
of them, is marked with the VRF (a conntrack label of its own), and
*Connections* shows it in the VRF column; choose a VRF at the top to see only
its connections (*Main (no VRF)*: those of none). *Reset* empties the whole
table.

As the table is shared, two connections with the same addresses and ports in
two VRFs at the same time would be one; with overlapping networks, keep NAT
from making them the same.

## The firewall's own services

The firewall's own services run outside the VRFs, and answer on the VRFs'
interfaces too: DNS, the DHCP server, router advertisements, NTP, SNMP, SSH and
the GUI. For that the agent sets, in a virtual firewall with VRFs:

- `tcp_l3mdev_accept` and `udp_l3mdev_accept`: sockets outside the VRFs accept
  what comes in on a VRF's interface;
- `ip_nonlocal_bind` (IPv4 and IPv6): a service may bind an address of a VRF's
  interface (named listens on each address of its interfaces);
- a rule per address of a VRF's interfaces, `from <address> iif lo lookup
  <the VRF's table>` (preference 1100): what the firewall sends from that
  address, such as a DNS answer, goes back through the VRF's table. The DHCP
  client adds and removes the rule of its address as it changes; other
  addresses are updated on commit.

So the DHCP server, DNS, NTP and SNMP can be turned on for interfaces in a VRF
like for any other (and their auto rules match them). What they fetch or ask
themselves (DNS resolving, NTP servers, DNS updates) goes through the main
table.

## VPN

A WireGuard interface can be put in a VRF: the tunnel's inside is then the
VRF's (its peers' networks go in the VRF's table), while its encrypted packets
are sent and received through the main table. A WireGuard tunnel whose
endpoint is reached only through a VRF is not supported, nor is a 6in4 tunnel
over a VRF.

## Limits

- 464XLAT (NAT64) is not supported on an interface in a VRF.
- EVPN's sessions are the main table's BGP's; a VRF takes part with its L3VNI.
- Rules can't name a VRF itself; name its interfaces, or an interface zone of
  them.
