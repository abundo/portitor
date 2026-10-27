<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Changelog

The major changes in each release. A release's notes on GitHub are its section
here (`dev/release-notes.sh`); the full list is `git log <previous tag>..<tag>`.

## v0.7.0

### New

- **portitor-config on every firewall:** each firewall holds its own configuration
  and serves the GUI and API itself (port 8444), so it can be changed when no portal
  is reachable. portitor-web becomes an optional portal with no configuration or
  users of its own: it passes the GUIs of one or more firewalls through at
  `/fw/<name>/`, with a firewall switcher in the top bar. The ISO sets up either
  layout.
- **HA pairs** (Admin → Firewalls, experimental): a secondary firewall that applies
  the primary's configuration with its own peer values, VRRP, Kea HA and conntrackd
  over an HA link, fencing without a quorum, a witness (portitor-config or
  portitor-web), a read-only replica of the database and promotion.
- **OpenVPN servers** (VPN → OpenVPN): an interface of type openvpn, UDP, TCP or
  adaptive (both, with separate tunnel addresses), logins checked against the
  users, a required role and the directory, client configs to download.
- **Directory** (Admin → Directory): users, roles and OpenLDAP/Active Directory
  servers, with LDAP groups mapped to roles.
- **Two-factor login** with TOTP and recovery codes.
- **VXLAN interfaces and BGP EVPN**, and **VRFs** with their own BGP, OSPF, IS-IS,
  VRRP, BFD and routes, and L3VPN over EVPN (L3VNI, type-5 routes).
- **IS-IS** (FRR's isisd) per virtual firewall
- **Policy routes** (Routing → Policy): route forwarded traffic by source,
  interface or service to another gateway or interface.
- **DNS blocklists** (Services → DNS → Blocklists): malware and phishing domains as
  response policy zones in BIND, refreshed on a schedule.
- **IP lists:** public blocklists to start from, refreshed on a schedule.
- **Rate limits:** the DNS, DHCP and NTP servers police what comes in to them; the
  Rate limits page shows traffic, drops and shaper queues.
- **Certificates:** certificate authorities, certificates made and signed here,
  DNS-01 through a DNS update client (following `_acme-challenge` CNAMEs), and an
  **ACME proxy** that gets certificates upstream for internal hosts.
- **Tools:** connectivity tests (ICMP, TCP connect, UDP) and iperf3 bandwidth tests.
- **Dashboard:** system information, CPU and memory, disk, traffic and logged
  packets.
- **Neighbours:** static ARP and ND entries. **Services:** custom port names for NAT
  port fields. **Connections:** a Show active switch.
- **Syslog** (Services → Syslog): the firewall's journal, followed live, and remote
  syslog servers (UDP or TCP, RFC 3164 or 5424, a minimum severity) that rsyslog
  sends it to.

### Changed

- Firewall names may be longer, with capitals, `-`, `_` and `.`.
- Page forms keep their title and Save button at the top; Settings has one Save.
- Kea's DHCPv4 server runs only with DHCPv4 subnets.
- Built with Go 1.26.10 and golang.org/x/net 0.60.0 (security fixes).

### Fixed

- **An apply no longer stops at the first failing step.** One failing command (a
  VLAN whose parent interface is down, say) left every interface after it down and
  without addresses, at boot too. The agent now sets up every interface, address,
  route and service it can and reports all the errors at the end; a commit with
  errors still fails and is rolled back.
- **DHCP after a reboot:** when renewing the saved lease fails, the DHCP and DHCPv6
  clients ask for a new lease at once instead of waiting for the old one to expire.
  They also try again as soon as their interface's link comes up (a cable plugged
  in, the switch port up) instead of after their next retry delay.
- Setup fills in the DNS servers that the DHCP server on the WAN offers; reverse
  path filtering dropped its answer.
- A renamed VLAN no longer clashes with its old device.
- Setup accepts a /31 address (a point-to-point WAN link).

### Upgrading

- An update installs rsyslog, disabled until the firewall has syslog servers configured.
- portitor-web's database moves to the firewall: portitor-config there owns it,
  and portitor-web becomes the portal to it at `/fw/<host name>/`. Everyone logs in
  again.
- **Firewall and portitor-web on one host** (the ISO): the update moves the database
  on that host.
- **portitor-web on a host of its own:** update from that host
  (`install.py` there, with SSH to the firewall as for `--agent`). It finds the
  firewall in its database, updates it first, copies the database (and the Revert
  snapshots) to the firewall's portitor-config, and lists it in `web.yaml`. An
  update of the firewall alone (from the GUI) leaves its portitor-config stopped:
  don't create an admin there, as a commit from that empty database would replace
  the firewall's configuration. A database that deploys to several firewalls is not
  moved: export each virtual firewall as a bundle and import it on its firewall.
- The anti-lockout rule also opens portitor-config's port (8444, `config_port` in
  `agent.yaml`) to `allow_from`, so the portal elsewhere reaches it.
- A certificate chosen under Settings for the GUI now applies to portitor-config;
  portitor-web serves the `tls_cert` in its `web.yaml`.

## v0.6.1

### New

- **WireGuard page:** Info and Configuration tabs.

### Changed

- Interface rate sparklines show bit/s instead of bytes/s.

### Fixed

- Kea is restarted on the first apply after the agent starts.
- The NTP Info tab works when the agent runs in dry-run.

## v0.6.0

### New

- **NAT64:** DNS64 and Jool translation per virtual firewall, on its own page
  under Network; translated traffic goes through the forward rules, NAT and
  shapers.
- **464XLAT:** per interface, PREF64 in router advertisements and DHCPv4
  option 108 (IPv6-only preferred).
- **NTP:** chrony per virtual firewall under Services, with an Info tab.
- **SNMP:** read-only net-snmp (v2c community, v3 users) per virtual firewall
  under Services.
- **6in4 tunnels:** an interface kind on the Interfaces page, with endpoint
  updates at Hurricane Electric's tunnel broker.
- **Interfaces:** renew a DHCP/DHCPv6 lease, and a Statistics dialog with
  packet, error and drop counters.
- **BGP info:** a neighbour's prefixes received, filtered and advertised, and
  its full neighbour information.
- **Routing page:** all routing tables, with protocol and the VF a gateway
  belongs to.
- **Dashboard:** each service's log (`journalctl --follow`) in a window of its
  own, one tab per service.
- **Updates:** a release marked broken ("Broken: <reason>" in its notes) is
  shown with a warning and never offered as the update.
- **ISO:** end-to-end test of the split setup in two VMs
  (`make iso-e2e-split`).

### Changed

- Commit is always shown; with no changes it applies the deployed config
  again, without a confirm.
- DHCP and RA settings follow a renumbered interface address.
- Menu: Routing is a top-level section after Network, all sections start
  collapsed, and Help's topics are grouped the same way.
- Backup & restore is its own page under Admin.
- GUI: automatic refresh is shown on its button and stops after an hour;
  every message is also kept in the log panel's Agent log tab, which has a
  filter; pages have no box around their content.
- DNS zone: the Records tab comes first; "Zone info" is now "Zone
  configuration".

### Upgrading

- An update installs the new Debian packages: chrony (replacing
  systemd-timesyncd), snmpd, jool-dkms and jool-tools with the kernel headers
  (DKMS builds Jool's module, which takes a while).
- Database migrations 44 to 50 run on update.

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
