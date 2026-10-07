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

Under *Network → Interfaces*, *New interface*, kind *VRF*:

- **Name**: the interface name, such as `blue`. A Linux `vrf` device of that
  name is made in the virtual firewall.
- **Table**: the VRF's routing table, 1 to 6399 (not 253 to 255, the kernel's
  own tables), unique in the virtual firewall.
- **VRF members**: the interfaces routed by the VRF. An interface is in at most
  one VRF or bridge; a bridge or VLAN can be a member.
- **Addresses**: usually none. An address on the VRF interface itself is an
  address of the firewall in the VRF, like a loopback's.

The members keep their addresses, DHCP client and router advertisements: a DHCP
default route and the routes learned from router advertisements go in the
VRF's table.

## Routes

A static route (*Network → Static routes*) goes in a VRF's table when its
**VRF** names the VRF, or when its interface is a member of one. A route in the
main table with the VRF interface itself as its interface sends traffic into
the VRF (route leaking); a route in the VRF to an interface outside it sends
traffic out of the VRF.

A WireGuard site peer's networks and a 6in4 tunnel's default route go in the
table of their interface's VRF.

*Network → Routing* shows every table, the VRFs' included.

## Rules

Rules and interface zones name a VRF's members like any other interface. For a
packet that comes in on a member, Linux gives the VRF device as the input
interface in the input and forward chains; the firewall therefore matches the
members by `meta sdifname` there (a rule that names members and other
interfaces is rendered as two). Naming the VRF interface itself in a rule
matches everything that comes in on any of its members.

## The firewall's own services

The firewall's own services (DNS, NTP, SSH, the GUI, BGP...) run outside the
VRFs. With a VRF in the virtual firewall, TCP and UDP sockets are set to accept
connections that come in on a VRF's member too (`tcp_l3mdev_accept`,
`udp_l3mdev_accept`), and the rules decide as usual. A TCP connection is
answered through the VRF; a UDP service may answer through the main table.

## Limits

- BGP, OSPF, VRRP and BFD run in the main table only: a neighbour or OSPF
  interface in a VRF won't work, and a static route with BFD can't be in a VRF.
- The DHCP server, router advertisements and DNS are best kept on interfaces
  outside VRFs.
