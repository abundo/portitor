<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Tunnels (6in4, Hurricane Electric)

When the Internet connection has no IPv6, a **6in4 tunnel** carries IPv6 inside
IPv4 (IP protocol 41) to a tunnel server that has it. Hurricane Electric gives
such tunnels away at [tunnelbroker.net](https://tunnelbroker.net), each with a
routed /64 (and a /48 on request).

A tunnel is an interface of the virtual firewall (kind `6in4`, a Linux `sit`
device). It is created under *Network → Interfaces* with the kind *6in4 tunnel
(Hurricane Electric)*, and is used in rules, interface zones and routes like any
other interface.

## Create the tunnel at tunnelbroker.net

1. Sign up and choose *Create Regular Tunnel*.
2. As *IPv4 Endpoint*, give the firewall's public IPv4 address. Hurricane Electric
   pings it first, before Portitor knows the tunnel: for this once, add an input
   rule that accepts the service `ping` on the WAN, and remove it afterwards.
3. Pick the tunnel server nearest to you.

The tunnel's page then shows, under *IPv6 Tunnel Endpoints*, the **Server IPv4
Address**, the **Server IPv6 Address** and the **Client IPv6 Address**, and under
*Routed IPv6 Prefixes* the /64 for your LAN. The *Tunnel ID* is at the top; the
*Update Key* is on the *Advanced* tab.

## Settings

Under *Network → Interfaces*, *New interface*, kind *6in4 tunnel (Hurricane
Electric)*; the form then shows the tunnel's fields:

- **Name**: the interface name, such as `he0`.
- **Server IPv4 address**: the tunnel server (*Server IPv4 Address*). IPv6-in-IPv4
  packets from and to it are accepted automatically (the auto rules `6in4 he0`).
- **Local IPv4 address**: the firewall's address the tunnel uses. Leave it empty
  (*any*) when the address comes from DHCP or the firewall is behind NAT.
- **IPv6 addresses**: the *Client IPv6 Address* with its prefix length, such as
  `2001:470:1f0a:12::2/64`.
- **IPv6 default route**: routes `::/0` through the tunnel (below).
- **MTU**: 0 is 1480, the tunnel's usual MTU. If you change it at
  tunnelbroker.net (*Advanced* tab), set the same here.
- **Tunnel ID**, **User name** and **Update key**: the Hurricane Electric account
  that keeps the tunnel's IPv4 endpoint up to date (below). Empty Tunnel ID: off.
  The update key is never shown again once saved; leave the field empty to keep it.

## IPv6 through the tunnel

The tunnel only connects the two ends. To use it:

1. Turn on **IPv6 default route** in the tunnel (on by default for a new one): the
   firewall routes `::/0` through the tunnel, with metric 512. A static `::/0`
   under *Routing → Static* still takes precedence.
2. Give a LAN interface an address of the *Routed /64* (such as
   `2001:470:1f0b:12::1/64`) and turn on router advertisements for it under *DHCP*,
   so the clients get addresses with SLAAC.
3. Allow the forwarding with rules, such as LAN → `he0` accept. The tunnel is the
   WAN of IPv6: rules that let IPv6 in from the Internet name `he0`.
4. Commit.

## Keeping the endpoint up to date

The tunnel server sends to the IPv4 endpoint it has been told. When the firewall's
address changes (a new DHCP lease), Hurricane Electric must be told the new one.
With a Tunnel ID, the agent does that itself, with Hurricane Electric's update API
(`https://ipv4.tunnelbroker.net/nic/update`):

- when the tunnel is committed, and whenever the virtual firewall's IPv4 address
  towards the tunnel server changes;
- once a day otherwise, so an address the firewall can't see (behind NAT) is
  corrected too;
- again after 5 minutes when it fails.

The request is made from the virtual firewall, through its routes and from its
address. It sends the firewall's address when that is public; behind NAT (or with
a private or carrier-grade NAT address) it sends none, and Hurricane Electric
takes the address the request comes from.

The *Endpoint update* column of the interfaces list shows the state: `ok` with the address Hurricane
Electric has, or `error` and why. A wrong user name or update key, an unknown
tunnel id or a block for too many updates is not retried until the address or the
settings change. "IP is not ICMP pingable" means Hurricane Electric's ping did
not get through.

## The ping check

Hurricane Electric pings a new endpoint before it takes it, from an address it
doesn't publish. No rule is needed for it: while the agent sends an update, the
auto rule `tunnel broker ping` answers pings to the address being sent, from
anyone, for 45 seconds (the `tunnelbroker_ping` set), and only then. Behind NAT,
the router in front must pass the ping on to the firewall as well.

## Behind NAT

A firewall behind a NAT router needs the router to forward IP protocol 41 to it
(often called *DMZ host*); port forwards can't, as protocol 41 has no ports. Leave
the local IPv4 address empty.
