<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# VXLAN and EVPN

A **VXLAN** carries ethernet inside UDP (port 4789) between VTEPs (VXLAN tunnel
endpoints), so one layer 2 segment can stretch over a routed network. Each
segment has a **VNI**, a number the same on every VTEP of it.

A VXLAN is an interface of the virtual firewall (kind `vxlan`, a Linux `vxlan`
device), created under *Network → Interfaces* with the kind *VXLAN*. It is
used in rules, interface zones and bridges like any other interface. To join a
LAN to the segment, make a bridge with the LAN port and the VXLAN as members.

The VTEPs are found one of two ways:

- **Static**: each VXLAN lists the other VTEPs (*Remote VTEPs*). Broadcasts and
  frames to unknown MAC addresses are sent to every one of them, and the VXLAN
  learns the MAC addresses behind each VTEP from the packets it receives.
- **EVPN**: BGP tells the VTEPs about each other and about the MAC (and IP)
  addresses behind them, in the L2VPN EVPN address family (RFC 7432, 8365). No
  list to keep up to date, and less flooding: the bridge answers ARP and
  neighbour discovery for the remote hosts itself.

## Settings

Under *Network → Interfaces*, *New interface*, kind *VXLAN*:

- **Name**: the interface name, such as `vx100`.
- **VNI**: 1 to 16777215; unique in the virtual firewall.
- **Local address**: the firewall's VTEP address, the source of the VXLAN
  packets. An address of the virtual firewall, often a loopback interface's so
  it stays up when a link goes down. EVPN needs it, and so do IPv6 remotes.
- **Underlay interface**: the interface the VXLAN packets leave by, and the only
  one they are accepted on. Empty: as the routing table says, accepted on any.
- **UDP port**: 0 is 4789. Linux's old default was 8472.
- **Remote VTEPs**: the other VTEPs' addresses, of one IP version. With EVPN, the
  VTEPs allowed to send to this one (empty: any).
- **MTU**: VXLAN adds 50 bytes (70 over IPv6). 0 leaves the kernel's default:
  the underlay interface's MTU less that, or 1450 without one. To carry
  1500-byte frames the underlay needs an MTU of 1550 or more.

VXLAN packets from the remote VTEPs (from anyone, with EVPN and no remotes) are
accepted automatically, on the underlay interface when one is set, and so are
the packets the VXLAN sends (the auto rules `vxlan vx100`). VXLAN has no
encryption or authentication: run it over a network you trust, or inside a
WireGuard tunnel (make the WireGuard interface the underlay).

## Static VTEPs

1. On each firewall, make a VXLAN with the same VNI, its own **Local address**
   and the others' addresses as **Remote VTEPs**.
2. Make a bridge with the VXLAN and the LAN port as members, and give the bridge
   the LAN's address if the firewall routes for it.
3. Commit.

## EVPN

EVPN runs in FRR's BGP (see [BGP](bgp.md)).

1. Make the VXLAN on each firewall as above, but with the **Local address** set
   and no remotes needed, and put it in a bridge (EVPN requires that).
2. Under *Routing → BGP*, turn on **EVPN** in the settings: the firewall
   advertises the VNIs of its VXLANs (`advertise-all-vni`).
3. On each neighbour (or peer group) to exchange EVPN routes with, turn on
   **Activate** under *L2VPN EVPN*. The neighbours are usually iBGP, often
   between the loopback addresses (with *Update source*) or through a route
   reflector (*Route reflector client* under *L2VPN EVPN*).
4. The other VTEPs' addresses must be reachable: announce the local addresses in
   IPv4 or IPv6 unicast, or with OSPF.
5. Commit.

FRR's zebra then reads the VNI from the VXLAN device and bgpd sends a type 3
route for it (the VTEP), and type 2 routes for the MAC and IP addresses learned
on the bridge. The VNIs and the routes are shown with
`vtysh -N <virtual firewall> -c 'show evpn vni'` and `-c 'show bgp l2vpn evpn'`
(the default instance: without `-N`).

Hosts on one layer 2 VNI reach each other through the VXLAN; traffic between
VNIs or out of the segment is routed by the firewall's interfaces in the
bridges, like any other LAN. EVPN itself (the sessions and `advertise-all-vni`)
is the main table's BGP's; a [VRF](vrf.md) joins it with a layer 3 VNI, below.

## L3VPN (layer 3 VNIs)

A VRF can be an L3VPN over EVPN: its routes are sent to the other VTEPs as EVPN
type 5 routes (RFC 9136) with a layer 3 VNI, and their routes for the same VRF
come into its table, routed to them through VXLAN (symmetric IRB). The VRFs of
one L3VPN at each firewall (or switch) share the VNI and route targets.

1. Set up EVPN in the main table as above: BGP with **EVPN** on and the
   neighbours that activate *L2VPN EVPN*. No layer 2 VNI is needed.
2. Under *Routing → VRF*, edit the VRF and give it an **L3VNI** (unique among
   the virtual firewall's VNIs), the **Local VTEP address** (as for a VXLAN)
   and, if wanted, the **Underlay interface** and **UDP port**.
3. Choose what to advertise (**IPv4**, **IPv6**) and, if the defaults don't
   suit the other end, the **Route distinguisher** and **Import** and **Export
   route targets** (ASN:NN or IPv4:NN). FRR's defaults are the router id and an
   index for the RD, and AS:VNI for the route targets, the AS being the VRF's
   BGP's: give the route targets when that differs from the main table's AS.
4. What the VRF advertises is what its BGP has: with BGP turned on in the VRF
   (*Routing → BGP* with the VRF chosen), its networks, redistribution and the
   routes from its neighbours (PE–CE); without, its connected networks and
   static routes.
5. Commit.

The firewall makes, for each such VRF, a VXLAN device `l3vx-<VNI>` (not
learning) and a bridge `l3br-<VNI>` in the VRF with it as its port; the bridge's
MAC address is the router MAC the other VTEPs send to. These names may not be
used for interfaces. FRR gets `vrf <name>` / `vni <VNI>` and, in `router bgp
<AS> vrf <name>`, the L2VPN EVPN address family with `advertise ipv4 unicast`
(and IPv6), `rd` and `route-target`. VXLAN packets to the L3VNI's port are
accepted automatically (on the underlay, when given). The routes are shown with
`vtysh -N <virtual firewall> -c 'show bgp l2vpn evpn route type prefix'` and
`-c 'show evpn vni'`, and in the VRF's table under *Routing → Tables*.

A layer 2 VNI's bridge can be put in a VRF with an L3VNI: zebra then ties the
two together, and the hosts on the segment are routed in the VRF as well.

## How it runs

The agent creates the VXLAN device (`ip link add ... type vxlan id <VNI> local
<address> dstport <port> dev <underlay>`) in the virtual firewall and
makes it again when the VNI, local address, port or underlay changes. Without
EVPN it learns from packets, and the agent keeps one all-zero forwarding entry
per remote VTEP (`bridge fdb append 00:00:00:00:00:00 dev vx100 dst <remote>`),
removing the ones of VTEPs no longer listed. With EVPN the device and its bridge
port don't learn (`nolearning`, `learning off`), the bridge port suppresses ARP
and ND (`neigh_suppress on`), and the forwarding entries are zebra's.
