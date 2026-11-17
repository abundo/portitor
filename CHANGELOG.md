<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Changelog

The major changes in each release. A release's notes on GitHub are its section
here (`dev/release-notes.sh`); the full list is `git log <previous tag>..<tag>`.

## Unreleased (1.1.0)

### Changed

- **portitor-web is portitor-manager**: the binary, its unit
  (`portitor-manager.service`), its config file (`/etc/portitor/manager.yaml`) and its
  data directory (`/var/lib/portitor-manager`). `install.py` moves an existing
  installation over (the old unit stopped and replaced, `web.yaml` and
  `/var/lib/portitor-web` moved). Until 1.2.0, `portitor-web` stays a symlink that runs
  portitor-manager with a warning, `web.yaml` is still read when `manager.yaml` is
  missing, and `install.py --web` is `--manager`. The ISO's machine type *web* is shown
  as *manager*. portitor-config keeps its name.
- **HA pairs are firewall clusters**, in the GUI, the messages, the CLI and the
  configuration's names. The leaves `ha-role` (its value `ha_link`: `cluster_link`),
  `ha-gateway`, `ha-monitor`, `ha-primary`, `ha-secret`, `ha-epoch`, `ha-witness`,
  `ha-preempt` and `ha-witness-secret` are `cluster-*`; the state's `system ha` is
  `system cluster` and `system ha-pair` is `system clusters`; portitor-manager's
  `ha-firewall` list is `cluster`. A stored configuration (the candidate, kept commits,
  backups, bundles, the replica's copy) is migrated when it is read. Until 1.2.0 the
  old names are taken in CLI and API paths, API bodies and the CLI's `set`, with a warning
  (the YANG extension `px:was`); NETCONF takes the new names only. SNMP keeps the objects' numbers; their names in `PORTITOR-MIB`
  follow. `portitor show ha` and `portitor request ha ...` are `show cluster` and
  `request cluster ...` (`ha` still works until 1.2.0), and `POST /api/ha/promote` is
  `/api/cluster/promote` (the old route stays until 1.2.0). The agent's wire protocol
  and the document between portitor-config and the agent are unchanged, so a cluster
  updates one firewall at a time.
- **The user guides are organised by task**: installing, a first LAN/WAN firewall,
  VPNs, backup and recovery, updates, lost connectivity, firewall clusters with a
  runbook, and portitor-manager, ahead of the feature guides. Implementation details
  moved out of them into `dev/` (`arch-*-guide.md`, `arch-moved-from-docs.md`).

- **No database.** portitor-config keeps everything in files in its data directory
  (the directory of `db.path`, which `config.yaml` keeps naming): the configuration
  tree, the users, roles, directory and firewalls in it, and the deployment log,
  counters and sessions beside it. portitor-config's own SQLite database, GORM code
  and migrations are gone; `portitor-config migrate` now only checks that it can read
  the data directory. The old `portitor.db` is left where it is, unread.
- **A restore no longer gives an id again** that was given after the backup was made
  (entries' ids, and rules' ids, which mark their connections).
- **The host's configuration is the top level of the configuration tree**, not an
  instance: in the CLI, NETCONF and `/api/config`, `interface eth1` is the host's
  interface and `instance guest interface eth1` a virtual firewall's, also with
  virtual firewalls on. The host's name is the leaf `host-name`; its own DNS
  templates are the firewall's (`dns-template` and the like at the top level),
  which every virtual firewall may use. Old paths (`instance main interface eth1`)
  are still taken, with a warning, until 1.2.0. SNMP: the host's state has new OIDs
  (`PORTITOR-MIB`), under the top level's `state`.
- **One firewall per configuration** (and its HA secondary): portitor-config refuses
  a second firewall of its own, as it did when it ran on the firewall.

### Upgrading

- **Update to 1.0.0 first.** An installation older than 1.0.0 is refused, by
  `install.py` and the GUI's update before anything is replaced, and by
  portitor-config at start ("update to Portitor 1.0.0 and start it once"): 1.0.0
  moves what the database holds into files and marks the data directory
  (`layout.json`). The path is 0.9.0, then 1.0.0, then 1.1.0.
- An HA pair: update both hosts together, the secondary first. A 1.1.0 secondary
  copies from a 1.0.0 primary; a primary before 1.0.0 is refused.
- A backup made before 1.0.0 (a database file) is refused, as in 1.0.0.
- 1.0.0's configuration (its candidate, kept commits, backups, bundles and an HA
  primary's copy) is read and moved to the new shape: the host's entries keep their
  ids, so rules keep their connection marks, and the firewalls get the same
  documents. The data directory is marked layout 3 and copies are format 3, which
  1.0.0 refuses ("update first"); so update an HA pair's secondary first.
- Until 1.2.0, scripts and clients that name the host as `instance <host-name>` keep
  working for paths below it and for the entry itself: the CLI and `/api/config`
  take them with a warning, NETCONF `edit-config` takes them (without one), and a GET
  of `instance=<host-name>` answers the host in 1.0.0's shape; a PUT of it is refused.
  What no longer has the host: the list `instance` (a GET of it, a NETCONF subtree
  filter on `<instance><name>…`), which holds the virtual firewalls alone. Drop the
  `instance` step.
- The host keeps its name (`host-name`), and is global admins' alone: a role can't
  grant it (a grant of it of 1.0.0 gives nothing, and goes at the next commit).

## v1.0.0

### New

- **An HA pair is one firewall in the portal** (*Add HA firewall*): add its primary
  and its secondary to it one at a time, and when the second is there the portal
  connects them over SSH, with nothing copied by hand, unless they are a pair
  already: it reads the secondary's details (`portitor-config secondary-info`), has
  the primary add and commit the secondary (`portitor-config add-secondary`), and,
  if you like, becomes the pair's witness. `portitor-setup --join` uses the same
  command. The pair is served at one path by whichever host is primary now
  (portitor-config's new `GET /api/pair` says whether it is a replica), and follows
  a failover.

- **HA preemption** (`ha-preempt` on the primary, default on): an active secondary
  hands back to the primary once the primary is heard again, closed and at least as
  healthy, for 30 s. A switchover by hand while the primary stays up is left alone.
- **Connectivity tests** have ARP ping, DNS query, and HTTP and HTTPS GET, besides
  ICMP, TCP and UDP.
- **The host's resolver** (`resolver-servers`, `resolver-from-dhcp` on the default
  virtual firewall): the agent writes `/etc/resolv.conf`, following the DNS servers
  of a DHCP lease. `portitor-config bootstrap` takes `--dns` and `--dns-from-dhcp`,
  and the installer's DNS field may be left empty to use DHCP's.
- **CLI:** a pager (`pager on|off`) and `| grep [-i] [-v]` filters on output.
- **Bash completion** for `portitor-agent`, `portitor-config`, `portitor-web` and
  `portitor-setup`.
- **The installer ISO needs no network**: it carries its packages in a repository
  of its own. The console's login screen shows the interfaces and their addresses,
  and the shell prompt shows the host's role.

### Changed

- **portitor-web is a standalone portal with a configuration of its own**: its
  firewalls, HA witness strings and users are a tree of a YANG module
  (`portitor-portal.yang`) in `portal.json` in its data directory
  (`/var/lib/portitor-web`), no longer lists in `web.yaml`. It has a login (make a
  user with `portitor-web createadmin`), a GUI of its own in the firewall GUI's
  look (the same layout, grids and dialogs), which opens each firewall's GUI as a
  page with a *Portal* button back, and
  adds a firewall by logging in to it over SSH once to read its address and
  certificate fingerprint (the host key is confirmed first; the credentials are not
  kept). `firewalls:` and `witness:` of an existing `web.yaml` are taken in once.
  It is kept as a firewall's configuration is, a candidate and what runs, and is
  reached by `portitor-web cli`, and the CLI and NETCONF over SSH (`ssh_listen`).
  portitor-config now allows being framed by the same origin, and has a
  `portal-info` command for the SSH step.

- **portitor-config keeps its state in files**, not in its database: the
  candidate, what runs of the users, roles, directory and firewalls
  (`global.json`), the ids, the commit counter, the deployment history, the known
  interfaces and the sessions' values, next to where the database was. The first
  start of this release moves what the database held into them (users, roles, the
  directory, firewalls, the ids, the history); the database is not written
  after that, and the release after this one does not read it, so **update to
  this release before the one after**. A database from before 0.9.0 is refused
  (update to 0.9.0 first, as before).
- **Backups are an archive** (`age -d backup | tar x`), the users, roles and
  directory with them: a restore brings them back. A backup made by a release before
  this one is a database file; restore it with the release that made it.
- **An HA pair is updated secondary first**, and together (see the HA guide).
- **CLI:** `back` goes up one level instead of switching between the last two
  contexts; `show interface` shows the configured kind (`physical` for a real NIC).
- **Auto rules:** the HA management ping is one rule for ICMP and ICMPv6, the
  portitor peer access one rule, and anti-lockout one row.
- **Setup:** the HA management gateway is optional (empty, the other host is the
  gateway); a portal host's first interface is Management, with one optional
  default gateway on either interface.

### Fixed

- The HA gate kept devices left down by name alone: two virtual firewalls with a
  device of the same name, or a restart, could bring the wrong one up. They are now
  kept per namespace and across restarts.
- A primary without its secondary yet was refused the peer as its management
  gateway.

### Upgrading

- **Update to 1.0.0 before any later release**: its first start moves what the
  database holds into files, and the release after it no longer reads the database.
  From before 0.9.0, update to 0.9.0 first.
- An HA pair: update the secondary first, then the primary, together.
- portitor-web has users of its own: make one with
  `sudo -u portitor-web portitor-web createadmin <user>` before logging in.

## v0.9.0

### New

- **HA pairs:** two firewalls as one active host and a passive standby with the
  same addresses and MAC addresses, replacing VRRP on a pair. A witness (the
  primary's portitor-config, or portitor-web) gives the vote; the standby's
  traffic interfaces are closed by a gate; connections survive a failover
  (conntrackd), and a lost carrier on a monitored interface or `portitor request ha
  switchover` hands the pair over. The standby's portitor-config is a read-only
  replica that can be promoted; ISO roles `primary` and `secondary` set a pair
  up. See [High availability](docs/ha.md).
- **Own DHCP server:** DHCPv4 and DHCPv6, and the IPv6 router advertisements,
  by Portitor's own `portitor-dhcpd`, replacing Kea and radvd. Leases are
  copied to an HA standby; DHCPv6 can serve a delegated prefix.
- **Command line:** the whole configuration from the console or over SSH, in the
  style of Nokia SR Linux: a shared candidate, `info`, `diff`, `commit confirmed`,
  `?` help and Tab completion, all from the configuration's YANG model (`yang/`).
  `portitor-config cli` as the user `portitor` on the console; `ssh_listen` in
  `/etc/portitor/config.yaml` for SSH, with the GUI's users and two-factor login.
  See [Command line](docs/cli.md).
- **NETCONF** on the same SSH port (subsystem `netconf`): the candidate, `edit-config`
  with every operation, subtree filters, confirmed commits, locks and `get-schema`,
  on the same YANG model.
- **State in the model:** interfaces and counters, routes, WireGuard peers, services,
  DHCP leases, neighbours, rule and rate-limit counters, BGP, OSPF, IS-IS, VRRP, BFD,
  NTP, NAT64, OpenVPN, the host and HA, read-only, in the CLI (`info from state`)
  and NETCONF `get`.
- **SNMP for the state:** the YANG state as PORTITOR-MIB, served through AgentX by
  portitor-config to the default instance's snmpd.
- **GUI:** every table is a data grid (resize, move and sort columns, a filter per
  column, cells edited in place); Hosts & prefixes shows an entry's form beside
  the tree; IP options have their own page, Firewall → Options; Renew on an ACME
  certificate orders it now; an HA primary badge in the top bar.
- **ISO:** the installed system has a serial console on `ttyS0` (115200 baud) as
  well as the screen: boot menu, kernel messages and a login. In Proxmox VE, add a
  serial port and use the xterm.js console, where copy and paste work.

### Changed

- The configuration is the tree alone: the SQLite database keeps users, roles,
  firewalls, the directory, deployments and known NICs, not the configuration.
  The GUI works through `/api/config` and names entries, never their ids.
- Syslog servers, certificate authorities and the DNS templates every virtual
  firewall may use are top-level lists.
- The Neighbours page groups by interface and shows the DHCP leases; of an HA
  pair, the active host's only.
- The dashboard has boxes around services, VPN and announcements.

### Fixed

- A second packet capture starts after the first.
- A key with a slash in it (a prefix such as `192.168.1.0/24`) was refused when
  edited through portitor-web, the portal.
- A disabled OpenVPN server may be without a certificate.
- echo is v5.4.1, which fixes the vulnerabilities reported in v5.3.1.

### Upgrading

- The update migrates the database: the configuration is read from its tables
  into the tree (the live commit's `deployed/<commit>-config.json` and
  `ids.json` next to the database, with the entries' ids kept) at the first
  start, and the tables are dropped. It is one way: take a backup first.
- Kea and radvd are stopped and masked by the update (their packages and lease
  files stay); Portitor's own server answers from then on, so a client's lease
  is renewed or re-requested rather than copied over.

## v0.8.0

### New

- **SYN proxy** for forward accept rules: SYN cookies answer the TCP handshake
  before the server sees it, against SYN floods.
- **Interfaces:** TCP MSS clamping (to the route's MTU, the interface's own or a
  fixed value) and a strict reverse path check that drops spoofed sources.
- **Drop IPv4 packets with IP options** (Settings), in input and forward, in every
  virtual firewall.
- **IP lists by country**, from the RIRs' delegations (ipverse, then ipdeny).
- **OpenVPN two-factor login:** a code from the user's authenticator app after the
  password, for the users with two-factor login or for everyone.
- **Certificates:** the certificate store as a tree by certification path, and an
  Import CA button on the Certificate authorities tab.
- Bash completion for the `portitor` command.

### Changed

- The GUI writes MAC addresses as `1122.3344.5566`; inputs also take colons and
  dashes.
- The ACME proxy is a tab of Services → Certificates.
- The rules table shows the description before From.
- The browser's title names the firewall's host.

### Fixed

- systemd-ssh-generator is masked: its AF_VSOCK errors filled the console.

### Upgrading

- An update installs bash-completion.

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
