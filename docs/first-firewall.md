<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# A basic LAN/WAN firewall

This guide starts where [Installing a firewall](install.md) ends: the firewall is
installed, and you are logged in to its GUI from the LAN. It covers what most
firewalls need: interfaces, rules, DHCP and DNS for the LAN, a port forward, and
committing the changes safely.

## How changes work

Nothing you change in the GUI reaches the firewall until you **commit** it.

1. Make your changes. A blue banner shows that there are uncommitted changes.
2. Click *Commit* in the banner, or open *Deploy* to review the changes first.
   *Preview* there shows exactly what will change.
3. The firewall applies the change, and a yellow banner counts down. Click
   **Confirm** to keep it.

If you don't confirm in time, the firewall goes back to the configuration it ran
before. So when a change cuts you off from the GUI, just wait: you get back in once
the timer runs out. *Revert* in the blue banner throws away all uncommitted changes.

## Interfaces

*Network → Interfaces* lists the network interfaces. The setup gave the LAN and WAN
their addresses and the labels *LAN* and *WAN*.

- To use another interface, for a guest network or a DMZ say, open it, turn it on,
  and give it an address such as `192.168.20.1/24`.
- A VLAN is a new interface of kind *VLAN* on a physical parent interface.
- An *interface zone* (*Network → Interface zones*) groups interfaces, so one rule
  can cover several of them.

## Firewall rules

*Firewall → Rules* has a tab for each kind of traffic. The two you'll use most:

- **Forward:** traffic *through* the firewall, for example from the LAN to the
  Internet.
- **Input:** traffic *to* the firewall itself, for example the GUI, SSH or ping.

Rules are checked from the top down, and the first one that matches decides. What
no rule accepts is dropped. Replies to accepted traffic are always let through, so
you never need a rule for return traffic.

The setup made these rules:

| Tab | Rule | What it does |
|---|---|---|
| Input | management from the LAN | The GUI and SSH from the LAN. |
| Input | ping from the LAN | Ping the firewall from the LAN. |
| Forward | LAN to WAN | Everything from the LAN to the Internet. |
| Postrouting | masquerade to the WAN | Gives traffic to the Internet the WAN address (NAT). |

**A guest network** that may reach the Internet but not the LAN needs a forward rule
from the guest interface to the WAN. There is no rule from the guests to the LAN, so
that traffic is dropped. Add a rule on the *Input* tab too if the guests should use
the firewall's DNS.

Be careful with *management from the LAN*. If you change it so that it no longer
matches your computer, you lose the GUI. Don't confirm, wait, and the change rolls
back.

More: [Writing firewall rules](rules.md).

## DHCP and DNS for the LAN

- *Services → DHCP*, the *DHCP server config* tab: turn the DHCP server on, open the
  LAN interface, and turn DHCP on for its prefix with a range. Clients get the
  firewall as their gateway and DNS server.
- *Services → DNS*, the *DNS server* tab: the firewall answers DNS on the interfaces
  you choose. Upstream it asks your provider's DNS servers, servers you list, or the
  root servers. *DNS zones* holds names you serve yourself, such as `nas.home.arpa`.
- A fixed address for a device: add an A record with the device's MAC address in a
  zone. The DHCP server then always hands that device that address.

## A port forward

To make a server on the LAN reachable from the Internet, for example a web server at
`192.168.1.10`:

1. *Firewall → Rules*, the *Prerouting* tab: add a rule on the WAN interface for TCP
   port 443, with action *DNAT* to `192.168.1.10`.
2. Commit and confirm.

Forwarded connections are allowed by default. Add a forward rule above them if only
some addresses may use the port forward. See
[Port forwards](rules.md#port-forwards).

## Next steps

- [Adding a VPN](vpn.md) for remote access or a link between sites.
- [Backup and recovery](backup.md): make a backup now, and again after big changes.
- [Updates](updates.md).
- *Status*: the *Dashboard* shows the firewall's health, traffic and services, and
  *Deploy → History* shows every change that was committed.
