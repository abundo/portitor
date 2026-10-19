<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Policy routing

The routing table chooses a route by the destination alone. A **policy route**
chooses it by more: where the traffic comes from, the interface it comes in on,
or its service. Common uses:

- a second Internet connection for some hosts or networks (the guest network,
  a server that must leave from a fixed address);
- one service by another way (video calls by the faster line, backups by the
  cheaper one);
- some traffic through a VPN or tunnel, the rest straight out.

Policy routes are made under *Routing → Policy*, per virtual firewall. They
apply to traffic **through** the firewall; what the firewall sends itself is
routed by the routing table.

## Settings

| Field | What |
|---|---|
| Incoming interfaces | Interfaces and interface zones the traffic comes in on; empty matches any. |
| IP version | Any, IPv4 or IPv6. The addresses and the gateway usually decide it. |
| Source addresses | Addresses, CIDRs, hosts and address lists by name, and IP lists (`@name`), as in a rule; empty matches any. |
| Destination addresses | The same, for the destination. A port forward (DNAT) changes the destination after the policy routes look at it, so they see the address the traffic was sent to. |
| Services | Services, as in a rule; empty matches any protocol. |
| Gateway | The next router: an address, or a host by name. A host with an IPv4 and an IPv6 address routes both IP versions; an address only its own. |
| Interface | The interface to send the traffic out of. With a gateway, the gateway's interface; alone, for a point-to-point interface (WireGuard, a 6in4 tunnel), it routes both IP versions out of it. |

A policy route with neither gateway nor interface is an **exception**: what it
matches keeps the routing table. Put it above a wider policy route, for the
traffic that must not take the other way (the local networks, say).

The policy routes are tried top to bottom, and the first that matches decides;
drag the grip to reorder them. A virtual firewall can have up to 256.

## Example: a second Internet connection

`eth0` is the first line, with the default route; `eth2` is a second line, its
router at 198.51.100.1. The guest network (zone `guest`) should leave by the
second line:

1. *Firewall → Rules*, postrouting: a masquerade NAT rule out of `eth2`, so
   the traffic leaves with the second line's address and its replies come
   back that way.
2. *Routing → Policy → New policy route*: incoming interfaces `guest`,
   gateway `198.51.100.1`, interface `eth2`.
3. A forward rule that accepts `guest` to `eth2` (the rules still decide what
   may pass; a policy route only chooses the way).

To keep the guests' traffic to the other local networks in the routing table,
add an exception above it: incoming interfaces `guest`, destination
`192.168.0.0/16`, no gateway.

## When the gateway is gone

While a policy route's route can't be used (its interface is down, has lost
its carrier or is not there), its traffic takes the routing table, as without
the policy route, and it comes back to the policy route when the link does. A
gateway that stops answering on a link that stays up is not noticed.

For the carrier, the agent sets `ignore_routes_with_linkdown` on the interface
the route leaves by: the policy route's interface, or the one with an address
in the gateway's network. Give the interface when the gateway is on an
interface with a DHCP address.

## Limits

- Interfaces in a [VRF](vrf.md) are not policy-routed, and a policy route can't
  send traffic into a VRF: policy routes are the main table's.
- Connections that come in on the second line are answered by the routing
  table, unless a policy route matches the replies too (their source is then
  the server behind the firewall).
- A gateway learned by DHCP can't be named yet; give the gateway's address.

## How it works

The policy routes become an nftables chain in prerouting (after the NAT64
chain) that marks the packets of each: the first policy route `0x5100`, the
second `0x5101`, and so on. For each, the agent adds a routing rule `fwmark
<mark> lookup <table>` and the policy route's default route in that table (6500
for the first, 6501 for the second...), both with protocol 99. The routes are
on the *Routing → Tables* page; on the firewall, `ip rule` and `ip route show
table all` list both. The forward chain clears the mark again once the packet
is routed, so the rate limits that shape traffic still mark it.
