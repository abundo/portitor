<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Writing firewall rules

The *Rules* page (under *Firewall*) decides which traffic each virtual firewall lets
through. This guide explains how the rules are evaluated, what each field means, and
how to build a rule set that is easy to read and safe to change.

## The chains

Each virtual firewall has five tabs, one per netfilter hook, in the order a packet
passes them: prerouting, then input (to the firewall) or forward (through it), output
for what the firewall itself sends, and postrouting last.

| Chain | Traffic | Typical use |
|---|---|---|
| **Prerouting** | as it arrives, before routing | port forwards (DNAT) |
| **Input** | to the firewall itself | SSH or the GUI from the LAN, ping |
| **Forward** | through the firewall, from one interface to another | LAN to Internet, access to a DMZ server, port forwards |
| **Output** | from the firewall itself | usually nothing: leave it open, or limit what the firewall may reach |
| **Postrouting** | as it leaves, after routing | masquerade (Internet sharing), source NAT |

Prerouting and postrouting hold NAT rules, which rewrite addresses; input, forward and
output hold the filter rules, which accept or drop.

A packet is checked against one filter chain only. Traffic from your LAN to the Internet is
*forward*; traffic from your LAN to the firewall's own address (its DNS server, say) is
*input*.

## How a chain is evaluated

Rules are evaluated **top to bottom, and the first match decides**. A packet that no
rule accepts is dropped by the chain's policy. Each chain runs in this order; the
locked rows show where the built-in parts sit. Before any chain, packets that fail an
interface's [reverse path check](#reverse-path-check) are dropped (a locked row in
input and forward).

1. **IP options** (input and forward, when switched on under Settings): IPv4 packets
   with IP options are dropped, before anything else. See [IP options](#ip-options).
2. **Established connections** are allowed. Rules only decide the *first* packet of a
   connection; the replies and the rest of the connection follow automatically. You
   never need a rule for return traffic.
3. **Invalid packets** (of no known connection) are dropped (a locked row at the top).
4. Loopback and the ICMP that IPv4 and IPv6 need to work are allowed.
5. **Auto rules** (input only, locked): what the configured services need, such as
   DHCP and DNS on the interfaces that serve them, WireGuard's port and ACME's port 80.
   In the default virtual firewall the agent's management port, SSH and the GUI
   (portitor-config) stay open to the agent's `allow_from` addresses (anti-lockout). They come before your rules, so
   a rule that closes an interface to the firewall still keeps DHCP and DNS working on it.
6. **Your rules**, in the order shown.
7. **Port forwards** (forward only, locked): connections a NAT port forward redirected
   are accepted *after* your rules, so a forward rule can still drop them, for example
   to allow a port forward from a few addresses only.
8. **The policy** (locked row at the bottom): everything else is dropped and counted.

## Fields of a rule

| Field | Meaning |
|---|---|
| Chain | input, forward or output. |
| Incoming interfaces | Where the packet comes in (not in output). Interfaces, link ends and interface zones. Empty matches any. |
| Outgoing interfaces | Where the packet leaves (not in input). Empty matches any. |
| IP version | any, IPv4 or IPv6. Addresses already decide it; set it only when the addresses are *any* or IP lists. |
| Services | What the traffic must match: `ssh`, `https`, `ping`, your own from the *Services* page. One of them must match; empty matches any protocol. |
| Source addresses | Addresses, CIDRs, names of hosts and address lists from *Hosts & prefixes*, or IP lists as `@name`. Empty matches any. |
| Destination addresses | The same, for the destination. |
| Action | **accept** lets it through; **drop** discards it silently; **reject** discards it and tells the sender (TCP reset, or ICMP port unreachable), so a client fails at once instead of waiting for a timeout. |
| Rate limit | A rate from the *Rate limits* page, which limits or shapes the rule's traffic. See [Rate limits](#rate-limits). |
| SYN proxy | Forward accept rules: answer the TCP handshakes with SYN cookies before the server sees them, against SYN floods. See [SYN flood protection](#syn-flood-protection). |
| Log matches | Every packet the rule matches shows in the log panel's *Logged packets* tab. |
| Enabled | A disabled rule stays in the list but is not deployed. New rules start disabled. |
| Description | Shown in the table, in the log and in the ruleset's comments. |

All fields of a rule must match for the rule to match. Within one field, any entry
may match: `Incoming interfaces: lan, guest` matches traffic from either.

**Empty means any.** An empty interface, service or address field does not limit the
rule at all. Interface lists are kept honest for you: renaming an interface or zone
updates the rules, and deleting one a rule uses is refused. A rule whose interface
list names only disabled interfaces is skipped rather than widened to *any*.

### IPv4 and IPv6

A rule may mix IPv4 and IPv6 addresses; it applies to each version its addresses
name. A rule without addresses applies to both, unless *IP version* says otherwise.
A host in *Hosts & prefixes* with both an IPv4 and an IPv6 address covers both.

## Building blocks

- **Interface zones** (*Firewall → Interface zones*) group interfaces: write
  `lan` once instead of `eth1, eth1.20, wg0`, and a new interface joins every rule
  of its zone.
- **Hosts & prefixes** give addresses names: `nas` instead of `192.168.1.10`. Change
  the address once and every rule follows on the next deploy.
- **Address lists** (*Hosts & prefixes*) name a group: addresses, prefixes, hosts by
  name and other address lists, IPv4 and IPv6 together. In a rule's source or
  destination a list becomes an nftables set (`A_<name>_v4` and `_v6`), so a long
  list is one fast lookup and one rule; a rule with an IPv4-only list is not rendered
  for IPv6. Used anywhere else (NAT, routes, DNS) a list stands for its addresses,
  like a host.
- **Services** (*Firewall → Services*) name protocols and ports. Predefined ones cover
  the common cases (`ssh`, `dns`, `https`, `ping`, `gre`); add your own for an
  application's ports. You can create one from the Service column's search too.
- **Rate limits** (*Firewall → Rate limits*) cap how often a rule matches; see
  [Rate limits](#rate-limits).
- **IP lists** (`@name`) are downloaded address lists, such as a public blocklist or
  CrowdSec decisions; see [Blocklists](blocklists.md) and
  [Blocking with CrowdSec](crowdsec.md).

## Rate limits

A rate limit (*Firewall → Rate limits*) is a rate a rule names in its *Rate limit*
field. When the rule matches, its traffic goes through the rate limit. Its *Mode*
says what happens to the traffic over the rate:

- **Police** drops it.
- **Shape** queues it, so the connections slow down without losing packets; see
  [Traffic shaping](shaping.md#shaping-a-rule). Mbit/s or kbit/s.

Police counts **Mbit/s** (bandwidth) or **packets per second**, with a burst: what
is allowed at once above the rate, in the same unit (0 is the default). It applies
to one of two things:

- **Whole connections** (the default): all the traffic, both ways, of the
  connections the rule accepts. Only an accept rule can name it. Use it to cap a
  host, a network or a service: "each guest at most 20 Mbit/s".
- **The packets the rule matches**, with *Whole connections* off. Established
  connections are accepted before the rules, so on an accept rule these are the
  **new connections**: slowing down SSH password guessing, or ping and connection
  floods. In packets per second.

- **Per source address** gives each source address its own rate, so one noisy
  client doesn't use up everyone's. For whole connections the address is the one
  that opened the connection, so a guest's downloads count against that guest. Off,
  all the traffic shares one rate.
- Rules that name the same rate limit share it.
- Renaming a rate limit updates the rules; deleting one a rule uses is refused.

The page shows each rate limit's traffic since the last commit, refreshed every 5
seconds:

- **Traffic**: what went through it, added up over the rules that name it. *In* is
  sent by the side that opened the connections and *out* is the replies, as on the
  rules list. Each comes with its rate over the last 5 seconds.
- **Dropped**: the packets a policer dropped for being over the rate. For a shaper,
  the packets its queues dropped. Hover over the cell for bytes and, for a shaper,
  the figures for each interface.
- A shaper's form lists its queue on each interface it sends on: what it sent and
  dropped, how many times it held packets back for being over the rate, and what
  is queued now. The rate applies on each interface separately.

Policing drops: TCP slows down when it loses packets, but it gets there by losing
them. To queue instead, use *Shape*, or shape the whole interface; see
[Traffic shaping](shaping.md).

Example: at most 1 new SSH connection a second from each address on the WAN (input),
with *ssh* policing 1 packet/s, burst 3, per source address, *Whole connections*
off:

| In | Out | Services | Source | Destination | Action | Rate limit |
|---|---|---|---|---|---|---|
| wan | | ssh | | | accept | ssh |

Example: each guest at most 20 Mbit/s (forward), with *guest host* policing
20 Mbit/s, whole connections, per source address:

| In | Out | Services | Source | Destination | Action | Rate limit |
|---|---|---|---|---|---|---|
| guest | wan | | | | accept | guest host |

### The services' rate limits

The DNS, DHCP and NTP servers answer anyone on the subnets they serve, so a
flood, a misbehaving client or an L2 loop on one subnet could keep them, and the
firewall, busy. Each has a rate limit of its own that polices
**every packet that comes in to it**, ahead of the established accept, so a
flow's later packets and a loop's copies count too. A virtual firewall starts
with one for each, *dns server*, *dhcp server* and *ntp server*, policing
1 Mbit/s, switched on by *Rate limit* on the DNS, DHCP and NTP pages. Tune them on
the Rate limits page (a rename is fine): the rate, the burst, or *Per source
address* so one client can't use up everyone's rate. The automatic rules on the
rules list (*Input*) show the rate limit next to *accept*, and *Dropped* on the
Rate limits page counts what it drops. A service's rate limit always polices; it
can't shape, and it can be deleted only while it is switched off (switching it on
again makes a new one).

## SYN flood protection

A SYN flood sends a server a stream of connection requests (TCP SYNs), often from
forged addresses, that never complete the handshake. Each one takes up a place in
the server's queue and an entry in the firewall's connection table.

**The firewall itself** is protected by SYN cookies, always on: when the queue of
one of its own services (the GUI, SSH, DNS over TCP) is full, it answers with a
cookie and keeps no state until the client answers.

**Servers behind the firewall** are protected by a rule's **SYN proxy**. The firewall
answers each SYN itself with a SYN cookie. Only when the client completes the
handshake does the firewall open the connection to the server and join the two. A
forged source never answers, so the server never sees it, and no connection entry
is made for it.

Switch on *SYN proxy* in a forward rule that accepts:

| In | Out | Services | Source | Destination | Action | |
|---|---|---|---|---|---|---|
| wan | | https | | web server | accept | SYN proxy |

- It applies to the rule's **TCP** services. The rule's other services (UDP 443 of
  *https*, for HTTP/3) are accepted as they would be without it. The rule needs at
  least one TCP service.
- The rule can't have **outgoing interfaces**: the firewall answers the SYN before it
  is routed. Narrow it by incoming interface and destination address instead.
- **Not for port forwards.** A port forward's connections are to an address of the
  firewall, which a SYN proxy leaves alone. Use it for servers with addresses of their
  own (routed, or in a DMZ).
- **MSS** and **window scale** are what the firewall tells the client about the
  server, so they must match the server. The MSS is 1460 by default (IPv4; IPv6 gets
  20 less): lower it when the server's link has a smaller MTU (1452 over PPPoE). The
  window scale is 7 by default, which suits Linux and most others; use 8 for Windows
  servers. A window scale lower than the server's makes transfers slower; a higher one
  loses packets.
- The rule counts, logs and rate-limits the proxied connections as usual. A rate
  limit must be one for whole connections, or a shaper.
- With a SYN proxy in a virtual firewall, its connection table no longer takes up a
  TCP connection it hasn't seen from the start. An established connection that
  wasn't in the table, after a reboot say, has to reconnect. On an HA pair, the
  connections synchronised to the other host carry on after a switch-over, but
  handshakes in progress during it fail and are retried by the client.

## IP options

An IPv4 header is 20 bytes; options (Record Route, Timestamp, Router Alert, Security,
...) make it longer. Normal traffic carries none, and options have been the way in for
kernel flaws. Source-routed packets (the LSRR and SSRR options) are always dropped;
the others are let through unless you switch on, under **Admin → Settings → IP
options**:

- **Drop packets with options to the firewall**: in the input chain. IGMP's membership
  reports carry the Router Alert option, so IGMP still comes in.
- **Drop packets with options when forwarding**: in the forward chain, to and from the
  hosts behind the firewall.

Both apply to every virtual firewall, from the next commit. The drop comes first in the
chain, before established connections are accepted, so it takes packets with options
in any connection, and no rule can let them through. A locked row *IP options* at the top
of the chain counts what it dropped.

## Reverse path check

Switch on **Reverse path check** on an interface (Network → Interfaces) to drop packets
that come in on it from a source address the virtual firewall would not route back out
of it: a host on the LAN pretending to be on the Internet, or packets from the Internet
claiming a LAN address. This is strict *unicast reverse path forwarding* (uRPF), PF's
`urpf-failed`.

- The check comes first, before connection tracking, NAT and the chains, so no rule can
  let such a packet through and it never opens a connection. A locked row *reverse path*
  in the input and forward chains counts what it dropped (one counter for both).
- The route back is looked up as for any packet, in the interface's VRF if it is in one.
  A source with no route at all fails too, so an interface whose networks aren't routed
  (a LAN behind another router without a static route for it) drops their traffic.
- Packets to a VRRP virtual router (Routing → VRRP) arrive on its device and must route
  back by its interface. The check is not available on an interface with VRRP in a VRF.
- DHCP clients asking for an address (from `0.0.0.0`), IPv6 duplicate address detection
  (from `::`), router advertisements and neighbour solicitations always pass.
- **Leave it off where routing is asymmetric on purpose**: a second uplink that is not
  the default route (replies to its traffic are routed out by the first), policy routes
  for traffic that comes in, or a network that reaches you by one path and is reached by
  another.

## MSS clamping

A TCP connection agrees on the largest segment each side will send (the MSS) in its
handshake, from each host's own link, usually 1460 bytes for a 1500-byte ethernet. When
a link on the way is smaller (a WireGuard, 6in4 or OpenVPN tunnel, a PPPoE uplink at
1492) the hosts are meant to find out by *path MTU discovery*, from the ICMP *too big*
messages; when something on the way filters ICMP, connections hang as soon as a full
packet is sent (a page that never finishes loading, an SSH session that stalls).

Switch on **Clamp TCP MSS** on the interface with the small MTU (Network → Interfaces):
the firewall lowers the MSS in the handshakes it forwards through it, so neither side
ever sends packets too big for it.

- **MSS 0** (the default) takes it from the MTU of the route each handshake leaves by,
  less the headers. Handshakes that come in on the interface are lowered to what its own
  MTU leaves, when that is known: set as the interface's MTU, or a WireGuard's (1420) or
  6in4 tunnel's (1480) default.
- **A fixed MSS**, the IPv4 one (IPv6 gets 20 bytes less), applies both ways: 1452 for
  PPPoE, 1380 for a WireGuard tunnel over IPv4.
- The MSS is only ever lowered, in both directions of a connection, whatever the rules
  decide. Connections to and from the firewall itself don't need it: its own TCP knows its
  links' MTUs.

## Fragmented packets

A packet too big for a link on its way may arrive in fragments, and only the first
fragment carries the TCP or UDP header with the ports. The firewall **reassembles
fragments before any rule sees them**: connection tracking needs whole packets, so the
kernel puts the fragments back together as they arrive, before NAT, the SYN proxy and
the chains. Every rule, in every chain, sees the whole packet, so services and ports
match fragmented traffic like any other, and no rule for fragments is needed.

- **Forwarded packets leave in fragments again.** After the forward chain the kernel
  splits the packet up: IPv4 into fragments no bigger than the largest one that came
  in, IPv6 into the sizes it came in. An IPv4 packet with *don't fragment* set that is
  too big for the outgoing link is dropped with an ICMP *fragmentation needed* to its
  sender; IPv6 is never fragmented by a router, so a packet too big gets an ICMPv6
  *packet too big*. Both kinds of ICMP are always allowed (see
  [How a chain is evaluated](#how-a-chain-is-evaluated)).
- **Incomplete fragments are dropped silently.** A packet whose fragments don't all
  arrive in time (30 seconds for IPv4, 60 for IPv6), or whose fragments overlap, is
  dropped before the chains: no rule, counter or packet log sees it. Each virtual
  firewall has its own memory for reassembly, so fragments sent to one can't fill up
  another's.
- **What sees fragments:** a packet capture shows the packets as they are on the wire,
  in fragments. Traffic shaping of received traffic sees the fragments as they come
  in, and shaping of sent traffic the fragments that leave.

## Working on the Rules page

- **Edit in place:** cells can be edited directly in the table; a change saves at once
  (it reaches the firewall on the next deploy).
- **Reorder:** drag a row by its grip. Order matters: first match wins.
- **Right-click a row** to insert a rule, a comment or a group above or below it,
  to copy a rule (the copy starts disabled) or to delete it.
- **Comments** are rows of text between rules; they also end up in the ruleset.
- **Groups** head the rows below them, up to the next group. A group's chevron folds
  them away in the view only: folded rules still apply. Deleting a group keeps its rules.
- **Counters** show the traffic of each rule since the last deploy, counted per whole
  connection, and the locked rows show what each chain drops by default. They update
  every few seconds while the page is open.
- **Locked rows** open read-only. Their *Log* box still works, so you can log the
  invalid packets, an auto rule or what the policy drops.

## Exporting and importing nftables

**Export nftables** on the Rules page downloads the virtual firewall's ruleset as
`<name>.nft`. You can download the live ruleset or the one with your uncommitted changes.
It is the whole file the firewall loads, the locked rows included. Rules that use an
IP list `include` the list's file on the firewall, so the file loads as it is only there.

**Import nftables** (for administrators) reads an nftables file, such as
`/etc/nftables.conf` from another firewall, into this virtual firewall:

1. Choose the file or paste it, then click *Preview*. The firewall reads it with
   `nft` apart from the running rules, so variables (`define`) work and syntax
   errors show with their line. `include` statements are refused: paste the included
   files in their place.
2. Map the file's interface names to this virtual firewall's interfaces or zones.
   Rules on an interface you leave unmapped are left out.
3. Check what would be created and the list of what is left out, each with the
   reason. *Replace* deletes this virtual firewall's rules and NAT rules first;
   otherwise the imported rules come after the existing ones.
4. Click *Import*. The rules are an uncommitted change: review them, then commit,
   or revert to discard them.

What is imported:

- Rules of filter chains on the input, forward and output hooks, in order. A chain's
  `policy accept` becomes a final accept rule, since Portitor's chains drop what no rule
  accepts.
- Matches on interfaces (`iifname`, `oifname`), addresses, destination ports, protocols,
  ICMP types and the IP version; `accept`, `drop`, `reject` and `log`. A rule's
  comment becomes its description.
- Regular chains reached by `jump` or `goto`, in place: each of their rules gets the
  jumping rule's matches too, and they go in a group of their own, named after the
  chain. After a `goto`, a rule applies the chain's policy to what went there, since
  it doesn't come back. A rule can't match the same field twice (an interface in
  both the jump and the rule, say); such a rule is left out.
- `dnat` in prerouting and `snat` and `masquerade` in postrouting nat chains, as
  port forwards and source NAT.
- A named set of addresses becomes a host/prefix of the same name. If a different one
  of that name exists, the new one is named `<name>-imported`. Ports and ICMP types
  become predefined services where one fits exactly (`ssh`, `dns`), and new services
  otherwise (`tcp-8080`).

What is left out: `ct state established,related accept`, `ct state invalid drop` and
loopback accepts, which Portitor adds itself; chains no imported chain jumps to; a
`return` with matches, and the rest of its chain; negated matches (`!=`); source ports; `limit` (use a [rate limit](#rate-limits));
interface wildcards; dynamic sets, maps and other statements.

## Examples

Internet access from the LAN (forward):

| In | Out | Services | Source | Destination | Action |
|---|---|---|---|---|---|
| lan | wan | | | | accept |

A web server in the DMZ, reachable from everywhere (forward; add a port forward on the
*Prerouting* tab if it has a private address):

| In | Out | Services | Source | Destination | Action |
|---|---|---|---|---|---|
| | dmz | http, https | | webserver | accept |

SSH to the firewall only from an admin network (input):

| In | Out | Services | Source | Destination | Action |
|---|---|---|---|---|---|
| lan | | ssh | admins | | accept |

Block known attackers before anything else (forward, at the top):

| In | Out | Services | Source | Destination | Action |
|---|---|---|---|---|---|
| wan | | | @crowdsec | | drop |

The guest network may reach the Internet but not the LAN (forward; reject so devices
fail fast):

| In | Out | Services | Source | Destination | Action |
|---|---|---|---|---|---|
| guest | lan | | | | reject |
| guest | wan | | | | accept |

## Port forwards

A port forward makes a server on an inside network reachable from outside. A
connection to a port on the firewall's WAN address is sent on to the server's address
and port. Port forwards are set on the *Prerouting* tab.

### How to set it up

Take a web server `192.168.1.10` on the LAN that should answer HTTPS on the WAN
address:

1. On the *Prerouting* tab, add a port forward.
2. **Incoming interfaces:** `wan`, where the connections come in.
3. **Protocol:** `tcp`, with **Destination ports** `443`.
4. **Target address:** `192.168.1.10`. Set a **Target port** only when the server
   listens on another port, for example outside port `8443` to port `443` inside.
5. Leave **Source addresses** empty to allow everyone, or limit them to the
   addresses that may connect.
6. Enable the entry, save and deploy.

**No filter rule is needed.** The forward chain accepts port-forwarded connections in
its locked *port forwards* row, after your rules. A forward rule above that row can
still stop them, for example the *Block known attackers* rule in the examples above.

### Destination addresses

**Destination addresses** match the address the client connected to, before the
translation. With *Incoming interfaces* set, you usually leave them empty. Set them
when:

- **The WAN has several public addresses**, and each address should go to a different
  server, or only one address should be forwarded.
- **The forward has no incoming interfaces.** It then matches on every interface: a
  LAN client connecting to *any* host on that port would be sent to your server.
  Setting the firewall's public address prevents that.

Leave them empty when the WAN address comes from DHCP and can change: a fixed address
would stop matching after the change.

## Port forwards from inside: hairpin NAT

A port forward (on the *Prerouting* tab) normally works only from outside: it
matches traffic that comes in on its incoming interfaces, usually the WAN. A LAN
client that uses the server's public name, say `nas.example.com`, which resolves to the
WAN address, reaches the firewall itself instead, and the connection fails. *Hairpin*
makes the port forward work from the inside too.

### How to set it up

1. On the *Prerouting* tab, open the port forward. It must have *Incoming
   interfaces* set, usually `wan`.
2. Turn on **Hairpin** and save.
3. Deploy.

No filter rule is needed: hairpinned connections are accepted by the locked *port
forwards* row in the forward chain, like those from outside. As with any port forward,
a forward rule above that row can still stop them. In the guest example above,
`guest → lan reject` also stops guests from reaching the NAS through its public address,
which is usually what you want; add an accept above it if not.

### What happens

Take a port forward `wan, tcp 443 → 192.168.1.10:443` with Hairpin on, and a LAN client
`192.168.1.50` that connects to the WAN address `203.0.113.7` on port 443:

1. The connection comes in on `lan`, not `wan`, so the ordinary port forward doesn't
   match. The hairpin copy of it does: it matches the same protocol, ports and
   addresses on **every other interface**, but only when the destination is one of the
   **firewall's own addresses**. It rewrites the destination to `192.168.1.10:443`.
2. The firewall forwards the connection to the NAS and **masquerades** it: the NAS sees
   it coming from the firewall's LAN address, not from `192.168.1.50`.
3. Without the masquerade, the NAS would answer `192.168.1.50` directly, on the same
   LAN, and the client would drop a reply from an address it never contacted. With it,
   the reply goes back through the firewall, which undoes both rewrites, and the client
   sees an answer from `203.0.113.7`.

Connections from outside are not affected: they still match the ordinary port forward
and keep their real source address.

### Things to know

- **The server sees the firewall as the client** for hairpinned connections. Its logs
  show the firewall's address, and an allow list on the server must include it.
- The hairpin matches **any address of the firewall**, unless the port forward has
  *Destination addresses*. Set them (the public address) if the firewall has several
  addresses and the forward should apply to one only.
- Hairpin needs *Incoming interfaces* on the port forward; without them the forward
  already matches every interface, and the firewall can't tell inside from outside.
- Split DNS (the public name resolving to the server's inside address on the LAN, set
  in the DNS zones) avoids the detour and keeps the client's address. Hairpin is the
  simpler choice when the public address changes or you don't run the LAN's DNS.

## Good practice

- **Specific before general.** Put narrow rules (a single host, a blocklist drop) above
  broad ones; a broad accept above them would decide first.
- **Accept what you need; let the policy drop the rest.** You rarely need a final drop
  rule; the policy row already drops and counts it.
- **Use names**, zones and services instead of raw addresses and ports; the table stays
  readable and changes happen in one place.
- **Describe** every rule that isn't obvious; the description shows in the log too.
- **Log while debugging.** Tick *Log* on a rule, or on the policy row, to see what it
  matches or drops; untick it when done.
- **Check the counters.** A rule whose counter stays at zero is never reached: it may be
  shadowed by a rule above it.
- **New rules start disabled**, so you can prepare a change and enable it when ready.

## Deploying safely

Changes take effect only when you deploy (see *Deploying* in
[portitor-web](portitor-web.md)). With *auto-rollback*, the firewall restores
the last confirmed configuration unless you click *Confirm* in time, so a rule that
locks you out undoes itself. The *Deploy* page previews the generated nftables ruleset
before you apply it.
