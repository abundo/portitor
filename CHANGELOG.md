<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Changelog

The major changes in each release. A release's notes on GitHub are its section
here (`dev/release-notes.sh`); the full list is `git log <previous tag>..<tag>`.

## v0.5.1

### Fixed

- **WireGuard endpoint names no longer leave the interfaces without addresses.**
  In v0.5.0, an apply set the WireGuard config before the interface addresses.
  When the agent applied while the addresses were missing (at boot, or after
  the agent restarted), the endpoint name could not be resolved, the apply
  stopped, and the firewall came up with no addresses and no way to reach DNS.
  The names are now set after the addresses and routes; one that does not
  resolve is logged and retried every minute.

### Upgrading

- Update from v0.5.0 as usual. A firewall left without addresses by this bug
  recovers once the new agent runs.

## v0.5.0

### New

- **OSPF:** OSPFv2 and OSPFv3 (FRR) per virtual firewall, with an info page
  for neighbours, interfaces and routes.
- **VRRP:** virtual routers (FRR's vrrpd) per virtual firewall.
- **BFD:** per interface, for static routes, OSPF and BGP neighbours.
- **BGP:** link-local neighbours on their interface, with IPv4 over IPv6
  (extended next hop); neighbours listed per peer group.
- **Loopback interfaces** (dummy) for router ids and BGP update sources.
- **Rate limits and shaping:** police or shape traffic per rule, and shape an
  interface's sending and receiving (CAKE).
- **Address lists:** named lists of addresses, prefixes, hosts and other lists,
  usable in any address field.
- **nftables import and export:** import an nftables file into a virtual
  firewall's rules, NAT, hosts and services (jumps into chains followed);
  export a virtual firewall's ruleset.
- **Certificates:** import a certificate with its key.
- **DNS:** forward-only zones; dynamic zones (DNS update clients) on the DNS
  page; DNS templates per virtual firewall, the default VF's optionally global.
- **Connections:** reset the conntrack table.
- **Tasks:** run a command with `/bin/bash -c`.
- **ISO:** setup shows its steps in a list beside the form, a GRUB entry for
  password recovery, and an end-to-end test (`make iso-e2e`).

### Changed

- NAT is on the Rules page, as the Prerouting and Postrouting tabs.
- The services' automatic accept rules for BGP neighbours and OSPF networks
  match nftables sets, listed read-only under Hosts & prefixes.
- Names have no limits beyond what Linux, nft, FRR, BIND and the file system
  need.
- BIND 9 comes from ISC's Debian repository (the stable version).
- Each user picks a date format, including MM-DD-YYYY and DD-MM-YYYY.
- The backup's file name holds the Portitor version.
- GUI: interface zones pick interfaces in a dual list, URLs follow the menu,
  the log panel shows the selected VF's lines, and route map, prefix, AS path
  and community list entries are reordered by drag and drop.

### Fixed

- Editing a WireGuard interface opens the form again.
- Save is enabled as soon as a form has loaded.
- Renaming a DNS zone keeps its type.

### Upgrading

- An update installs the Debian packages the agent needs that are missing,
  FRR's included, and adds ISC's BIND repository where the release has one.

### Known issues

- **Interfaces can lose their addresses with WireGuard endpoint names:** fixed
  in v0.5.1; use that instead.
