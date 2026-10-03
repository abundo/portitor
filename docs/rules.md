<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Writing firewall rules

The *Rules* page (under *Firewall*) decides which traffic each virtual firewall lets
through. This guide explains how the rules are evaluated, what each field means, and
how to build a rule set that is easy to read and safe to change.

## The three chains

Each virtual firewall has three tabs, one per chain:

| Chain | Traffic | Typical use |
|---|---|---|
| **Input** | to the firewall itself | SSH or the GUI from the LAN, ping |
| **Forward** | through the firewall, from one interface to another | LAN to Internet, access to a DMZ server, port forwards |
| **Output** | from the firewall itself | usually nothing: leave it open, or limit what the firewall may reach |

A packet is checked against one chain only. Traffic from your LAN to the Internet is
*forward*; traffic from your LAN to the firewall's own address (its DNS server, say) is
*input*.

## How a chain is evaluated

Rules are evaluated **top to bottom, and the first match decides**. A packet that no
rule accepts is dropped by the chain's policy. Each chain runs in this order; the
locked rows show where the built-in parts sit:

1. **Established connections** are allowed. Rules only decide the *first* packet of a
   connection; the replies and the rest of the connection follow automatically. You
   never need a rule for return traffic.
2. **Invalid packets** (of no known connection) are dropped (the locked row at the top).
3. Loopback and the ICMP that IPv4 and IPv6 need to work are allowed.
4. **Auto rules** (input only, locked): what the configured services need, such as
   DHCP and DNS on the interfaces that serve them, WireGuard's port and ACME's port 80.
   In the default virtual firewall the agent's management port and SSH stay open to
   the agent's `allow_from` addresses (anti-lockout). They come before your rules, so
   a rule that closes an interface to the firewall still keeps DHCP and DNS working on it.
5. **Your rules**, in the order shown.
6. **Port forwards** (forward only, locked): connections a NAT port forward redirected
   are accepted *after* your rules, so a forward rule can still drop them, for example
   to allow a port forward from a few addresses only.
7. **The policy** (locked row at the bottom): everything else is dropped and counted.

## Fields of a rule

| Field | Meaning |
|---|---|
| Chain | input, forward or output. |
| Incoming interfaces | Where the packet comes in (not in output). Interfaces, link ends and interface zones. Empty matches any. |
| Outgoing interfaces | Where the packet leaves (not in input). Empty matches any. |
| IP version | any, IPv4 or IPv6. Addresses already decide it; set it only when the addresses are *any* or IP lists. |
| Services | What the traffic must match: `ssh`, `https`, `ping`, your own from the *Services* page. One of them must match; empty matches any protocol. |
| Source addresses | Addresses, CIDRs, names from *Hosts & prefixes*, or IP lists as `@name`. Empty matches any. |
| Destination addresses | The same, for the destination. |
| Action | **accept** lets it through; **drop** discards it silently; **reject** discards it and tells the sender (TCP reset, or ICMP port unreachable), so a client fails at once instead of waiting for a timeout. |
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
- **Services** (*Firewall → Services*) name protocols and ports. Predefined ones cover
  the common cases (`ssh`, `dns`, `https`, `ping`, `gre`); add your own for an
  application's ports. You can create one from the Service column's search too.
- **IP lists** (`@name`) are downloaded address lists, such as CrowdSec decisions or a
  blocklist; see [Blocking with CrowdSec](crowdsec.md).

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

## Examples

Internet access from the LAN (forward):

| In | Out | Services | Source | Destination | Action |
|---|---|---|---|---|---|
| lan | wan | | | | accept |

A web server in the DMZ, reachable from everywhere (forward; add a port forward on the
*NAT* page if it has a private address):

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
and port. Port forwards are set on the *NAT & port forwards* page, not on the Rules page.

### How to set it up

Take a web server `192.168.1.10` on the LAN that should answer HTTPS on the WAN
address:

1. On the *NAT & port forwards* page, add an entry of kind **Port forward (DNAT)**.
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

A port forward (a *dnat* rule on the *NAT* page) normally works only from outside: it
matches traffic that comes in on its incoming interfaces, usually the WAN. A LAN
client that uses the server's public name, say `nas.example.com`, which resolves to the
WAN address, reaches the firewall itself instead, and the connection fails. *Hairpin*
makes the port forward work from the inside too.

### How to set it up

1. On the *NAT* page, open the port forward (kind *dnat*). It must have *Incoming
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
