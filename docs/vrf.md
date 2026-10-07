<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# VRFs

A **VRF** (virtual routing and forwarding) gives some interfaces of a virtual
firewall a routing table of their own. Traffic that comes in on them is routed
by that table only, apart from the rest of the virtual firewall, so two VRFs can
have their own default routes and overlapping networks.

Each virtual firewall has its own network namespace, so its VRFs are its own:
two virtual firewalls can each have a VRF called `blue` with table 10, and they
have nothing to do with each other.

## Settings

VRFs are made under *Routing → VRF*, *New VRF*:

- **Name**: such as `blue`. A Linux `vrf` device of that name is made in the
  virtual firewall, so it is at most 15 characters and not the name of an
  interface or interface zone. Renaming a VRF keeps its interfaces in it.
- **Table**: its routing table, 1 to 6399 (not 253 to 255, the kernel's own
  tables), unique in the virtual firewall.

An interface is put in a VRF under *Network → Interfaces*, with its **VRF**
field; *—* is the main table. Changing the field moves the interface to another
VRF, or back to the main table. Any kind of interface can be in a VRF, but a
bridge's member goes with its bridge: put the bridge in the VRF. A VRF that
interfaces or routes are in can't be deleted.

The interfaces keep their addresses, DHCP client and router advertisements: a
DHCP default route and the routes learned from router advertisements go in the
VRF's table.

## Routes

A static route (*Routing → Static*) goes in a VRF's table when its **VRF**
names the VRF, or when its interface is in one. A route in a VRF to an
interface outside it sends traffic out of the VRF (route leaking).

A WireGuard site peer's networks and a 6in4 tunnel's default route go in the
table of their interface's VRF.

*Routing → Routing* shows every table, the VRFs' included.

## Rules

Rules and interface zones name the interfaces in a VRF like any other. For a
packet that comes in on one, Linux gives the VRF device as the input interface
in the input and forward chains; the firewall therefore matches those
interfaces by `meta sdifname` there (a rule that names interfaces in VRFs and
others is rendered as two).

## The firewall's own services

The firewall's own services (DNS, NTP, SSH, the GUI, BGP...) run outside the
VRFs. With a VRF in the virtual firewall, TCP and UDP sockets are set to accept
connections that come in on an interface in a VRF too (`tcp_l3mdev_accept`,
`udp_l3mdev_accept`), and the rules decide as usual. A TCP connection is
answered through the VRF; a UDP service may answer through the main table.

## Limits

- BGP, OSPF, VRRP and BFD run in the main table only: a neighbour or OSPF
  interface in a VRF won't work, and a static route with BFD can't be in a VRF.
- The DHCP server, router advertisements and DNS are best kept on interfaces
  outside VRFs.
- Rules can't name a VRF itself; name its interfaces, or an interface zone of them.
