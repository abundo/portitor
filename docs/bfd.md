<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# BFD

BFD (Bidirectional Forwarding Detection, RFC 5880 and 5881) notices within a
fraction of a second that a directly connected neighbour has stopped forwarding.
The two ends send each other small UDP packets several times a second; when a few
in a row are missing, the session is down and the routing that uses it reacts at
once, without waiting for its own, much slower, timers:

- a **static route** is withdrawn while its gateway is unreachable, so a route with a
  higher metric (or one learnt from BGP or OSPF) takes over;
- an **OSPF** neighbour is dropped without waiting for the dead interval (40 s by
  default);
- a **BGP** session goes down without waiting for the hold time (180 s by default).

Portitor runs BFD with [FRR](https://frrouting.org)'s `bfdd`, single hop (to
neighbours on the same network), in every virtual firewall with BFD on an interface.
FRR must be installed on the firewall (`apt install frr frr-pythontools`), as for
[BGP](bgp.md).

## Turning it on

BFD is turned on in two places, and runs only where both say so:

1. **On the interface**, under *Network → Routing → BFD*, tab *Interfaces*: *New BFD
   interface*, with the interface and its timers. This is the switch: disable the row
   (or delete it) and nothing uses BFD on that interface any more.
2. **On what uses it**, with its *BFD* switch:
   - a static route (*Network → Routing → Static routes*): its gateway is watched;
   - an OSPF interface (*Network → Routing → OSPF*, tab *Interfaces*): the
     neighbours on it are watched;
   - a BGP neighbour or peer group (*Network → Routing → BGP*): the neighbour is
     watched. A peer group's switch counts for each of its neighbours.

A static route, OSPF interface or BGP neighbour with BFD on, whose interface has no
BFD, runs as if the switch were off. A BGP neighbour uses BFD on the interface with a
network that holds its address (or, for a link-local neighbour, its own interface);
one that is not directly connected (loopback peering, eBGP multihop) gets no BFD.

The other end must run BFD too: a session only comes up when both ends send.

## Timers

| Setting | Default | |
|---|---|---|
| Receive interval | 300 ms | How often the peer may send (10-60000 ms). |
| Transmit interval | 300 ms | How often this firewall sends, at the most (10-60000 ms). |
| Detect multiplier | 3 | How many packets may be lost before the peer is down (2-255). |
| Passive | off | Wait for the peer to start the session. |

Each end sends at the slower of its own transmit interval and the other's receive
interval, so with the defaults a lost neighbour is noticed after 3 × 300 ms = 0.9 s.
Shorter intervals notice sooner, but a busy firewall or link may then miss packets
and take a healthy neighbour down.

## Static routes with BFD

A static route with BFD is not installed by the agent like the others but by FRR
(`staticd`), which installs it while the BFD session to its gateway is up and
withdraws it while it is down. Such a route needs a gateway, and its metric is FRR's
administrative distance (0-255; 0 is FRR's default, 1): among routes to the same
destination, the lowest distance wins. A backup route through another gateway is an
ordinary static route with a higher metric, or a second BFD route with a higher
distance.

"Redistribute static" in BGP and OSPF includes the routes with BFD.

## The firewall rules

BFD's control packets (UDP port 3784) are let in and out on the interfaces with BFD
by auto rules, before your own rules, as for OSPF and BGP.

## BFD info

The tab *BFD info* shows the sessions as FRR has them: the peer and interface,
**up**, **down** or **init**, how long, the timers on each end, and why the session
last went down (the diagnostic). On the firewall, `portitor show bfd` prints the same.
