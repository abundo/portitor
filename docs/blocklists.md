<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Blocklists

A blocklist is a public list of addresses known for attacks, botnets or spam. Portitor
downloads it into an IP list and refreshes it on a schedule. Your rules then use the
list as `@name`. The lists below are free and need no account. For CrowdSec, which
needs an engine or a Console account, see [Blocking with CrowdSec](crowdsec.md). To
block malware and phishing domains in the DNS server instead, see
[DNS blocklists](dns-blocklists.md).

## The lists

| Blocklist | What it holds |
|---|---|
| Spamhaus DROP (IPv4) | Hijacked netblocks and ranges run by criminals. Very few false positives: start here. |
| Spamhaus DROPv6 (IPv6) | The same, for IPv6. |
| FireHOL level 1 | Spamhaus DROP, Feodo, DShield and the bogons combined. It holds the private ranges (10.0.0.0/8, 192.168.0.0/16, ...), so use it only on traffic from the Internet. |
| abuse.ch Feodo Tracker | Botnet command-and-control servers. Best as a destination, to stop infected hosts calling home. |
| DShield top 20 attackers | The 20 /24 networks attacking most. |
| CINS Army | Addresses with a poor reputation score. Larger, with more false positives. |
| Emerging Threats block IPs | Compromised hosts, DShield and Spamhaus DROP. |
| blocklist.de (all) | Hosts that attacked SSH, mail, web and other services in the last 48 hours. Changes by the hour. |

## Adding one

1. *Network → Hosts & prefixes*, button *+ IP list*.
2. Pick the list under *Blocklist*. This fills in the name, description and URL.
3. *Refresh* is on, with a schedule at a random time between 02:00 and 04:59 every
   night. A random time keeps firewalls from all fetching at once. Change the schedule
   if you like: every few hours for blocklist.de, for example. Spamhaus asks for no more
   than one download an hour.
4. Save. This also adds a task that downloads the list again, on each firewall, named
   after the list. It is listed under *Services → Scheduled tasks*.
5. Add the rules (below) and deploy. The agent downloads the list right away; after
   that, the task downloads it again on its schedule.

The *Blocklist* and *Refresh* fields appear only for a new list. To change the
schedule later, edit the task.

## Rules that use it

*Firewall → Rules*, near the top of their chain, since the first match decides:

- **input**, incoming interface your WAN, source `@spamhaus-drop`, action drop. This
  protects the firewall itself.
- **forward**, the same. This covers port forwards and anything else reaching your
  network.
- **forward**, outgoing interface your WAN, *destination* `@feodo`, action drop. This
  stops infected hosts inside from reaching their botnet's servers.

A list matches IPv4 and IPv6, so each rule covers both. Traffic to a port you haven't
opened is already dropped by the default policy; an input or forward block matters
most for the ports you do open.

## Other lists

Any list served over http(s) works, with *Blocklist* left at *None*, source *URL*. One
entry per line:

- an address or prefix: `192.0.2.0/24`. Only the first word counts, and `#` and `;`
  start comments.
- a range, as two addresses: `192.0.2.0 192.0.2.255`. Anything after them is ignored.
- a JSON object with a `cidr`: `{"cidr":"192.0.2.0/24"}`.

A download that holds entries but no address (an HTML error page, say) fails. The last
good list then stays in force. Hosts & prefixes shows the error under *IP lists*.
