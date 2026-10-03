<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# portitor-web

portitor-web is the management GUI and REST API. It keeps the configuration in
an SQLite database and pushes it to portitor-agent on the firewall. Run it on another host, not
on the firewall itself. Installing it is covered in the [README](../README.md#install).
The [installer ISO](appliance.md) is the exception: it puts portitor-web on the
firewall, for a single-box setup.

## Configuration

`/etc/portitor/web.yaml` (`-f` picks another file):

| Key | Default | |
|---|---|---|
| `bind` | `127.0.0.1:8080` | Listen address. `start --bind` overrides it. |
| `jwt_secret` | | Signs session cookies. At least 32 characters: `openssl rand -base64 32`. |
| `tls_cert`, `tls_key` | | Serve HTTPS directly. Set both or neither. A certificate chosen under *Settings → Portitor web* takes their place; see [The GUI's own certificate](#the-guis-own-certificate). |
| `db.path` | `/var/lib/portitor-web/portitor.db` | SQLite database. Its directory must be writable by the service user (`-wal` and `-shm` files go next to it). |
| `dev` | `false` | Serves the frontend from disk and drops the cookie's Secure flag. Development only. |

Without `tls_cert`, keep `bind` on localhost and put a TLS reverse proxy in front. The
session cookie is marked Secure, so the GUI does not work over plain HTTP. The proxy
must pass WebSocket upgrades for the console.

## Commands

```sh
# as the service user (sudo -u portitor ...); as root it refuses
portitor-web start                 # serve the GUI and API
portitor-web migrate               # apply database migrations; start never migrates
portitor-web createadmin <user>    # create an admin, or reset a user's password and make them admin
portitor-web agent-url             # print the agent URL from Settings (used by install.py)
portitor-web bootstrap ...         # first configuration of an ISO install (portitor-setup runs it)
```

`createadmin` asks for the password twice on a terminal, or reads one line from stdin.
`-d` turns on debug logging. `--version` prints the version.

After an upgrade, run `migrate` before `start`. `install.py` does both.

## First steps

1. Log in with the user from `createadmin`.
2. On the firewall, run `portitor-agent init --host <address>`. It prints a token and
   the agent's certificate fingerprint.
3. *Admin → Settings → General*: enter the agent URL (`https://<address>:8443`), the
   token and the fingerprint, and save. The badge next to *Save* says whether the agent
   answers.
4. portitor-web adds the firewall's physical interfaces to the default virtual firewall `main`
   as they are configured now, and says so. Check them under *Network → Interfaces*.
5. Configure addresses, rules and services, then deploy.

## The screen

- **Virtual firewall selector** (top bar). Most pages show one virtual firewall, the one selected here.
  DNS templates, users and settings are shared by all virtual firewalls.
- **Agent badge** (top bar). The generation the agent has applied; yellow if its last
  apply had an error, red if portitor-web cannot reach it.
- **Log panel** (terminal icon) opens a panel at the bottom with three tabs:
  - *Agent log*: the agent's log.
  - *Logged packets*: the packets of the rules with *Log* ticked on the Rules page, as a
    table (time, virtual firewall, chain, rule, action, interfaces, protocol, source address and
    port, destination address and port, TCP flags or ICMP type). The destination port
    shows its service name from the firewall's `/etc/services`, such as `443 (https)`.
    Every row can log, whatever its action: your rules
    log every packet they match; the locked rows (invalid packets, the auto rules of
    the services, anti-lockout, and the last row, what no rule matched) log at most 10
    packets a second. The filter keeps the rows that contain every word typed, such as
    `wan tcp 443`. The agent keeps the latest 2000 packets; they are not written to the
    kernel log.
  - *DNS queries*: the queries to the DNS servers with *Query logging* on (*DNS → DNS
    server*), as a table (time, virtual firewall, client address and port, name, class,
    type, BIND's flags, the server address asked). Only the queries that pass the
    virtual firewall's filters are kept (clients, names with the names below them, query
    types; an empty filter matches any). The search keeps the rows that contain every
    word typed. The agent keeps the latest 2000 queries; BIND also writes every query to
    the journal of its unit (`portitor-named@<vf>`).
- **Console window** (square terminal icon) opens a shell on the firewall, in the
  selected virtual firewall's network namespace, in a separate window.
- **Changes banner** (blue). Shows when the configuration differs from what is on the
  firewall. *Review* opens the Deploy page, *Commit* applies at once with the default
  auto-rollback, and *Revert* discards every uncommitted change: the configuration
  goes back to what the firewall runs (users and the agent connection stay). Each
  commit keeps a copy of the database in `deployed/` next to it for this; the last
  five are kept.
- **Confirm banner** (yellow). Shows while an apply waits for confirmation; see below.

## Menu

| Section | Page | What |
|---|---|---|
| | Dashboard | The selected virtual firewall on the firewall: interfaces, WAN lease, WireGuard peers, missing programs. |
| | Deploy | Check, preview, apply, history. |
| Globals | Virtual firewalls | Virtual routers. `main` is the host; others are network namespaces. |
| | Links | veth pairs between virtual firewalls. |
| | DNS templates | SOA templates, DNSSEC policies and zone templates, shared by all virtual firewalls. |
| Network | Interfaces | Physical, VLAN, bridge, WireGuard interfaces with their IP addresses (IPv4 and IPv6, as many as needed, each with its prefix length: `192.168.1.1/24`); WAN DHCP client, and a DHCPv6 client that can also ask for a delegated prefix (prefix delegation). An IPv6 address in another interface's delegated prefix is written relative to it, so a new prefix from the ISP renumbers it: with `2001:db8:1000::/48` delegated to wan0, `<wan0>:2000::1/64` is `2001:db8:1000:2000::1/64` (subnet `2000`, at most 4 hex digits, goes between the delegated prefix and /64; host `::1`). Its /64 is announced with router advertisements (SLAAC) automatically; DHCPv6 service on a delegated prefix is not supported. Until the prefix is delegated, such addresses are left out. A *Label* such as WAN is shown before the name wherever an interface is picked: WAN (ens18). The *Virtual firewall* field moves one, with its addresses, to another virtual firewall. *LLDP* (physical, VLAN and bridge interfaces, off by default) announces the firewall with LLDP on the interface and lists the neighbours it hears there under *Neighbours*. |
| | Routes | Static routes. |
| | Neighbours | What the virtual firewall's interfaces see next to them, by interface: the LLDP neighbours heard on interfaces with LLDP on (the info button shows everything the neighbour's LLDP frame said: system, port, VLANs, management addresses, capabilities), and the ARP (IPv4) and ND (IPv6) tables. On the firewall itself, as root, `portitor show lldp neighbours` (`--detail` for everything) and `portitor show ip neighbours` print the same; `-i <vf>` limits them to one virtual firewall, `--json` prints JSON. |
| | Hosts & prefixes | One tree with three top-level nodes: *Hosts*, named addresses usable wherever addresses are entered; *IP lists*, downloaded address lists (CrowdSec, blocklists) used as `@name` in rules, see [Blocking with CrowdSec](crowdsec.md); hosts and IP lists can be sorted into folders, which only structure the page; *Prefixes & IP addresses*, the prefix tree with prefixes, addresses and DNS names. The interfaces' addresses and their prefixes are listed automatically, and so are the addresses of the DNS zones' A and AAAA records that fall in a prefix (editing one opens its zone); a prefix that serves DHCP shows a *DHCP server* badge, one with SLAAC a *SLAAC* badge (set under DHCP). |
| Firewall | Interface zones | Named groups of interfaces for rules and NAT. |
| | Rules | Input, forward and output rules, with per-rule traffic counters and counts of what each chain drops by default (invalid packets, no rule matched); every row, the locked ones included, can log to the log panel's *Logged packets*. The Service column names the services a rule matches (empty: any protocol); its search can create a new one. See [Writing firewall rules](rules.md). |
| | Services | What the rules' Service column matches: TCP, UDP or SCTP port ranges (with source ports if wanted), an ICMP or ICMPv6 type and code, or an IP protocol number. Your own next to predefined ones such as `ssh`, `dns`, `ping` or `gre`. Also lists the port names (`https`) that NAT port fields accept. |
| | NAT & port forwards | Masquerade, SNAT and DNAT; a DNAT with Hairpin also works from the LAN to the public address. |
| Services | DNS | Two tabs. *DNS zones*: the zones and records the virtual firewall serves; their templates are under *Globals → DNS templates*. *DNS server*: the virtual firewall's DNS server (BIND), which always runs; its upstream (forwarders, the root servers, or the DNS servers from the DHCP lease on one interface, configured as BIND's forwarders; forwarding can fall back to the root servers); the interfaces it answers on; query logging, with filters, to the log panel's *DNS queries*. |
| | DHCP | Two tabs. *Leases*: active leases, and the leases of the firewall's own DHCP clients. *DHCP server*: the virtual firewall's DHCP server (Kea) on or off, its domain name and lease time, and the interfaces with the prefixes of their addresses, each with a DHCP switch. Badges on an interface: *DHCP Client* (it gets its IPv4 address by DHCP), *SLAAC-C* (it takes an IPv6 address from router advertisements), *RA* (it sends router advertisements). Edit an interface for its range, gateway and DNS servers, and on IPv6 prefixes router advertisements and SLAAC. Several prefixes with DHCP on one interface form a Kea shared network: clients get addresses from all of them. |
| | WireGuard | Tunnels, road-warrior and [site-to-site](#site-to-site-wireguard) peers; generates client and site configs. |
| | DNS update | Keeps DNS records in step with an interface's addresses (the WAN, say): on your own nameserver (by IP address or DNS name, looked up in the virtual firewall) by RFC 2136 dynamic update (TSIG signed), sent from the virtual firewall, or at a DNS hosting provider through its API, called from the firewall host (Bunny DNS, Cloudflare, deSEC, easyDNS, Gandi, GleSYS, GoDaddy, Hetzner DNS, Loopia, Namecheap, NameSilo, netcup, Njalla, OVHcloud, Porkbun). A provider's tokens and keys are stored on the server and never shown again; leave one empty to keep it. |
| | Certificates | TLS certificates from Let's Encrypt, got and renewed by the firewall; see [Certificates](#certificates). |
| | Scheduled tasks | IP list downloads and commands on a cron schedule. |
| Tools | Console | A shell on the firewall as the agent's `console_user`, in the network namespace of the selected virtual firewall (so `ip addr`, `nft list ruleset` and `ping` see that virtual firewall). *Open in window* (or the square terminal icon) opens one in a window of its own for that virtual firewall. |
| | Packet capture | Live capture with Wireshark in the browser. tcpdump runs on an interface of the selected virtual firewall (or *any*), with a capture filter (pcap syntax) and limits (packets, seconds, bytes per packet); the packets stream in as they are captured, into a packet list with Wireshark's display filters (`dns \|\| tcp.port == 443`), protocol tree and bytes. *Follow* keeps the newest packet in view. *pcap* downloads the capture for Wireshark. *Open in window* runs the capture in a window of its own, for the selected virtual firewall, so it keeps going while you use the rest of the GUI; each window is a capture of its own. The stream from the agent is capped at the rate under *Settings* (1000 kbit/s by default); when traffic outruns it, the firewall drops captured packets rather than fall behind. The agent's own API connection is left out, and at most two captures run at once. Wireshark (Wiregasm, about 20 MB) loads when the page opens; it is a separate program (GPL-2.0) that the installer puts in `/usr/share/portitor/wiregasm`. |
| | Traceroute | A traceroute like MTR, run on the firewall in the selected virtual firewall with `mtr`. Pick a *source interface* (*None*, the default, lets the routing table decide) and a *destination*: an IPv4 or IPv6 address, a named host or a DNS name, which the firewall resolves (for a name with both, *IP version* picks; IPv4 by default). One probe per hop goes out each second for the given rounds (10 by default); each hop's row shows its address, loss, sent and the last, average, best and worst round trip and its standard deviation, updated as replies come. *Stop* ends it early. |
| Admin | Updates | Debian package upgrades, Portitor releases, reboot. See [Installer ISO and updates](appliance.md#updates). |
| | Settings → General | The GUI's certificate, agent connection, default auto-rollback, packet capture rate, [backup and restore](#backup-and-restore). |
| | Settings → Users | GUI users and their roles. |
| | Settings → Roles | Groups of users, one per virtual firewall and your own; see [Roles](#roles). |
| | Help | This guide and the other guides in `docs/`. |

Your own name and password are under the user menu (top right).

## Users and sessions

A user is an **admin** or a **viewer**.

- An admin can do everything: manage the other users, deploy, open the console, run
  tasks, download a backup (with every secret in it), update and reboot the firewall.
  Give this role only to someone you would give root.
- A viewer can read the configuration of every virtual firewall, the deploy preview, the
  firewall's status, leases, rule counters and logs. A viewer can't change anything
  except their own name and password. They can't see WireGuard client configs, which
  hold private keys, and they can't use the console, Updates, Settings or Users.
  Portitor-web refuses a viewer's changes; the GUI hides the buttons for them and
  shows *Read-only* in the top bar.

New users get the role you pick in Settings → Users. Users that existed before roles
were added are admins. You can't change your own role, so at least one admin always
remains. Changing another user's role ends their sessions.

### Roles and virtual firewalls (multi-tenancy)

Besides admin and viewer, a user's own role can be **none**: no access of their own,
only the virtual firewalls their roles grant. Settings → Roles groups users; a user can be
in any number of roles, and is an **admin** or a **viewer** in each.

- Every virtual firewall has a role of its own, `vf-<name>`, which grants that
  virtual firewall. It is added with the virtual firewall, renamed with it and removed (members and
  all) when the virtual firewall is deleted; you can't rename or delete it by hand.
- A role you make yourself grants the virtual firewalls you pick for it. Names starting with
  `vf-` are kept for the virtual firewalls' roles.
- On each virtual firewall a user gets the highest level any of their roles gives; a global
  viewer reads every virtual firewall anyway.

A **virtual firewall admin** changes their virtual firewall's interfaces (but not which physical
NICs it has: a global admin adds, renames and removes those), zones, rules, NAT,
routes, IP addresses, DNS, DHCP, DNS update and WireGuard, its settings (not its
name, nor which virtual firewall is the default), captures its packets (*Tools → Packet
capture*) and **deploys** it. An
**virtual firewall viewer** reads it. Neither sees the other virtual firewalls, their status, leases,
counters or logged packets, nor the agent's log, Settings, Updates, Users or Roles.
Named hosts and prefixes, services, IP lists, DNS templates, tasks and links are
shared: everyone reads and uses them, a global admin changes them.

A virtual firewall admin's deploy takes their virtual firewalls from the database and everything
else as the firewall runs it, so another tenant's unfinished changes stay where they
are. They can confirm or roll back their own deploy; one change waits for
confirmation at a time, firewall-wide. A global admin deploys the whole database,
every tenant's changes included, unless they pick virtual firewalls under *Virtual firewalls* on the
Deploy page: then, like a virtual firewall admin's deploy, only those come from the database.
A virtual firewall admin with several virtual firewalls can pick some of them the same way. Before a virtual firewall admin can deploy, a global admin
must have deployed once. *Revert* (a global admin's) needs the last deploy to be one
of everything: it restores the database as it was then.

An admin can reset another user's password: open the user and pick *Reset password*,
then enter the new password twice. Your own password is changed under *Change
password*, which asks for the current one.

A login lasts 12 hours, or 30 days with *Remember me*. Changing your password ends
your other sessions; deleting a user, changing their role or resetting their password
ends theirs, and so does `portitor-web createadmin` for an existing user. An open
console closes within a few seconds when its session ends or expires. *Log out* only
clears the cookie in that browser: a copy of the cookie stays valid until it
expires. To end every session of a user at once, change the password. Changing
`jwt_secret` ends every session of every user.

## Deploying

Edits are saved in the database only. Nothing changes on the firewall until you apply.

On *Deploy*:

1. The top of the page validates the whole configuration. Problems listed there must be
   fixed first; *Apply* stays disabled until then.
2. *Preview* renders every file the agent will write and shows the difference from what
   it runs now.
3. *Apply* sends the configuration. The agent validates it again, checks the rulesets
   with `nft -c`, and switches over. The log of what it did is shown below.

**Auto-rollback.** After an apply the yellow banner counts down. Click *Confirm* to
keep the change; if you do nothing, the agent restores the last confirmed configuration
when the time runs out. If the change locked you out, wait. The default time is set
under *Settings*; the field on the Deploy page overrides it for one apply, and `0`
applies without confirmation. While an apply is pending, you cannot apply another one:
confirm it or roll it back first. The first apply has nothing to roll back to, so it
never waits for confirmation. If the agent restarts or crashes while a change is
pending, it rolls back when it starts again. A rollback that fails leaves the change
pending and is tried again every minute; the agent log says why it failed.

*History* lists every generation with who applied it and its status (applied,
confirmed, pending, rolled back, failed).

## Site-to-site WireGuard

A WireGuard interface serves road warriors (phones, laptops) and other sites alike. A
peer is a site when it has *Networks*: the networks behind it, e.g. the other office's
LAN `192.168.50.0/24`.

- *Allowed IPs* holds the peer's tunnel address only. Its networks are allowed through
  the tunnel too, and the agent routes them to the WireGuard interface; you add no
  static route. A network can't be `0.0.0.0/0` (add a static route through the
  interface for that) or be routed twice, by two peers or by a static route with
  metric 0.
- *Endpoint* makes this firewall connect to the site, with *Keepalive* (e.g. 25) to keep
  the tunnel up through NAT. Leave the endpoint empty on the side that waits. When the
  endpoint is a name, the agent looks it up again while the peer has had no handshake
  for over two minutes, so a site on a dynamic address (with DNS update) is found
  again.
- The config button of a site peer gives a wg-quick config for the router at the other
  site: this virtual firewall's prefixes under *Hosts & prefixes* (its interfaces' included) as its AllowedIPs, without the
  peer's own networks, and no DNS. If the other side is a Portitor too, enter the
  values there instead: its own WireGuard interface, and this firewall as a site peer
  with this side's networks.
- Allow the traffic with forward rules between the WireGuard interface (or its interface
  zone) and the LAN, in both directions as needed. NAT is not needed between sites.

## Certificates

*Services → Certificates* gets TLS certificates from Let's Encrypt (ACME) with the
HTTP-01 challenge: the CA fetches a token from `http://<domain>/.well-known/acme-challenge/`
for every domain of the certificate.

- Every domain must resolve (A, and AAAA if it has one) to an address of the
  certificate's *Interface*, the WAN say. DNS update can keep those records.
- The virtual firewall's input chain has an auto rule, *acme http-01*, for TCP port 80 on the
  interfaces of its certificates. It matches only while the firewall answers a
  challenge (the port is in the nftables set `acme_http` then; the set is empty the
  rest of the time), so port 80 is closed otherwise. A port forward (DNAT) of port 80
  on that interface takes the CA's requests elsewhere: remove it, or get the
  certificate on the server behind it.
- The firewall answers in the virtual firewall itself, on port 80; the ACME API is called from
  the firewall host.
- A certificate is ordered when it is deployed, when its SANs, common name, CA or key type
  change, and renewed when two thirds of its lifetime have passed (30 days before the
  end of a 90-day one). A failed order is tried again after 10 minutes, then after
  twice as long each time, up to 12 hours.
- The chain and key are in `<state_dir>/certificates/<vf>/<name>/`
  (`fullchain.pem`, `privkey.pem`, root only); the *State* column shows where, until
  when it is valid, and the last error. ACME accounts, one per CA and email, are in
  `<state_dir>/acme/`.
- Try *Let's Encrypt staging* first: its certificates are not trusted, but its rate
  limits are far higher than production's (5 failed validations per hour per domain).

### The GUI's own certificate

portitor-web can serve HTTPS with one of these certificates: choose it under
*Settings → Portitor web*. That takes effect without a restart, but needs
portitor-web to serve HTTPS itself: `tls_cert` and `tls_key` in `web.yaml` (the
ISO's setup sets them to a self-signed certificate), with `bind` on an address the
browser reaches, e.g. `0.0.0.0:443`. It fetches the chain and key from the agent
at once, every hour after and when the choice changes, and uses a renewed one
without a restart. The last one fetched is kept next to the database
(`tls-certificate.pem`, 0600), so a restart while the agent is unreachable still
has it; before the first is fetched, and when none is chosen, portitor-web serves
`tls_cert`, and tries again every minute. The certificate's domain must be the name you browse
to. The agent hands out the key to anyone with its token, which portitor-web already holds.
The service unit lets the `portitor` user listen on port 443
(`CAP_NET_BIND_SERVICE`).

## Backup and restore

*Settings → General → Backup* downloads the whole configuration database, encrypted with
a passphrase you choose (at least 10 characters). The file holds every secret (WireGuard
keys, TSIG secrets, IP list credentials, the agent token), so keep the passphrase safe;
it cannot be recovered. The file is in [age](https://age-encryption.org) format:
`age -d portitor-….db.age > portitor.db` gives the SQLite database.

*Restore* takes such a file and its passphrase, or an unencrypted `portitor.db`. It
checks the file, upgrades a backup from an older Portitor version (a backup from a newer
version is refused), and replaces the configuration in one step. It keeps:

- the users, so you stay logged in,
- the deployment history,
- the agent connection under *Settings* (URL, token, fingerprint), when one is set, so a
  backup restores onto a reinstalled firewall.

Restore changes only the database. Review the changes on *Deploy* and apply them as
usual. Restore is refused while an apply waits for confirmation.

## Secrets

The agent token, WireGuard private and preshared keys, TSIG secrets and IP list
passwords and API keys are never sent back to the browser, with two exceptions: an
encrypted [backup](#backup-and-restore), and the config button of a WireGuard peer,
whose wg-quick config holds the peer's private key (when it was generated here) and
the preshared key. Treat that config like a password: hand it over securely and
delete the downloaded copy. Their fields are empty when
you open a form. Leave them empty to keep the stored value, or enter a new one to
replace it.
