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

Only layer 2 VNIs are supported: hosts on one VNI reach each other through the
VXLAN; traffic between VNIs or out of the segment is routed by the firewall's
interfaces in the bridges, like any other LAN. Layer 3 VNIs (symmetric IRB)
need VRFs, which Portitor does not have.

## How it runs

The agent creates the VXLAN device (`ip link add ... type vxlan id <VNI> local
<address> dstport <port> dev <underlay>`) in the virtual firewall's namespace and
makes it again when the VNI, local address, port or underlay changes. Without
EVPN it learns from packets, and the agent keeps one all-zero forwarding entry
per remote VTEP (`bridge fdb append 00:00:00:00:00:00 dev vx100 dst <remote>`),
removing the ones of VTEPs no longer listed. With EVPN the device and its bridge
port don't learn (`nolearning`, `learning off`), the bridge port suppresses ARP
and ND (`neigh_suppress on`), and the forwarding entries are zebra's.
