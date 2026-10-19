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
portitor-web reset-2fa <user>      # turn off a user's two-factor login (portitor-config reset-2fa on a firewall)
portitor-web agent-url [--all]     # print the first (or every) firewall's agent URL (used by install.py)
portitor-web bootstrap ...         # first configuration of an ISO install (portitor-setup runs it)
```

`createadmin` asks for the password twice on a terminal, or reads one line from stdin.
`-d` turns on debug logging. `--version` prints the version.

After an upgrade, run `migrate` before `start`. `install.py` does both.

## First steps

1. Log in with the user from `createadmin`.
2. On the firewall, run `portitor-agent init --host <address>`. It prints a token and
   the agent's certificate fingerprint.
3. *Admin → Firewalls*: edit the firewall and enter the agent URL
   (`https://<address>:8443`), the token and the fingerprint, and save. Its *Status*
   column says whether the agent answers.
4. portitor-web adds the firewall's physical interfaces to the default virtual firewall `main`
   as they are configured now, and says so. Check them under *Network → Interfaces*.
5. Configure addresses, rules and services, then deploy.

## The screen

- **Virtual firewall selector** (top bar). Most pages show one virtual firewall, the one selected here.
  Users and settings are shared by all virtual firewalls.
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
    the journal of its unit (`named` for the default virtual firewall,
    `portitor-named@<vf>` for the others).
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
| Network | Interfaces | Physical, VLAN, bridge, loopback (a dummy interface that stays up, for a router id or a BGP update source) and WireGuard interfaces with their IP addresses (IPv4 and IPv6, as many as needed, each with its prefix length: `192.168.1.1/24`); WAN DHCP client, and a DHCPv6 client that can also ask for a delegated prefix (prefix delegation). An IPv6 address in another interface's delegated prefix is written relative to it, so a new prefix from the ISP renumbers it: with `2001:db8:1000::/48` delegated to wan0, `<wan0>:2000::1/64` is `2001:db8:1000:2000::1/64` (subnet `2000`, at most 4 hex digits, goes between the delegated prefix and /64; host `::1`). Its /64 is announced with router advertisements (SLAAC) automatically; DHCPv6 service on a delegated prefix is not supported. Until the prefix is delegated, such addresses are left out. A *Label* such as WAN is shown before the name wherever an interface is picked: WAN (ens18). The *Virtual firewall* field moves one, with its addresses, to another virtual firewall. *LLDP* (physical, VLAN and bridge interfaces, off by default) announces the firewall with LLDP on the interface and lists the neighbours it hears there under *Neighbours*. |
| | Routing → Routing | The virtual firewall's IPv4 and IPv6 routes in all its routing tables on the firewall (main, local and any other), with the protocol that added each: connected, DHCP, RA, portitor (static routes), BGP, OSPF, FRR's static routes. |
| | Routing → Static | The static routes. |
| | Routing → Routing objects | Prefix lists (IPv4 and IPv6), AS path lists, community lists and route maps, which BGP and OSPF use by name. See [BGP](bgp.md). |
| | Routing → BGP | Two tabs. *BGP info*: the neighbours' sessions (state, uptime, prefixes received and sent) and the BGP table, as FRR has them. *Configuration*: BGP on or off (off by default), local AS, router id, networks, aggregate addresses, redistribution, peer groups and neighbours. See [BGP](bgp.md). |
| | Routing → OSPF | Four tabs. *OSPFv2 info* and *OSPFv3 info*: the router id, neighbours (state, role, uptime), interfaces, areas and routes, as FRR has them. *OSPFv2 config* and *OSPFv3 config*: OSPF on or off (off by default), router id, reference bandwidth, area types, network statements (OSPFv2), area ranges, external summaries, redistribution of connected networks, static routes and BGP, and the interfaces OSPF runs on, with their area, cost, timers and MD5 key (OSPFv2). See [OSPF](ospf.md). |
| | Routing → VRRP | Two tabs. *Virtual routers*: VRRP virtual routers (VRRPv3 for IPv4 and IPv6, or VRRPv2), each on an interface with its id, virtual addresses, priority, advertisement interval and preempt. *VRRP info*: master or backup per virtual router and IP version, as FRR has them; on the firewall, `portitor show vrrp` prints the same. See [VRRP](vrrp.md). |
| | Routing → BFD | Two tabs. *Interfaces*: BFD on an interface, with its receive and transmit intervals and detect multiplier; static routes, OSPF interfaces and BGP neighbours with their *BFD* switch on use it there. *BFD info*: the sessions, up or down, as FRR has them; on the firewall, `portitor show bfd` prints the same. See [BFD](bfd.md). |
| | Neighbours | What the virtual firewall's interfaces see next to them, by interface: the LLDP neighbours heard on interfaces with LLDP on (the info button shows everything the neighbour's LLDP frame said: system, port, VLANs, management addresses, capabilities), and the ARP (IPv4) and ND (IPv6) tables. On the firewall itself, as root, `portitor show lldp neighbours` (`--detail` for everything) and `portitor show ip neighbours` print the same; `-i <vf>` limits them to one virtual firewall, `--json` prints JSON. The *Static entries* tab adds permanent ARP (IPv4) and ND (IPv6) entries: an address always resolved to the given MAC on an interface; an entry goes with its interface. |
| | Hosts & prefixes | One tree with four top-level nodes: *Hosts*, named addresses usable wherever addresses are entered; *Address lists*, named lists of addresses, prefixes and hosts or other address lists by name, which share their names with the hosts and are an nftables set in a rule's source or destination; *IP lists*, downloaded address lists (CrowdSec, blocklists) used as `@name` in rules, see [Blocking with CrowdSec](crowdsec.md); hosts and address and IP lists can be sorted into folders, which only structure the page; *Prefixes & IP addresses*, the prefix tree with prefixes, addresses and DNS names. The interfaces' addresses and their prefixes are listed automatically, and so are the addresses of the DNS zones' A and AAAA records that fall in a prefix (editing one opens its zone); a prefix that serves DHCP shows a *DHCP server* badge, one with SLAAC a *SLAAC* badge (set under DHCP). |
| Firewall | Interface zones | Named groups of interfaces for rules and NAT. |
| | Rules | One tab per hook, in the order packets pass them: *Prerouting* (port forwards, DNAT; with Hairpin a port forward also works from the LAN to the public address), *Input*, *Forward* and *Output* filter rules, and *Postrouting* (masquerade and SNAT). The filter rules have per-rule traffic counters and counts of what each chain drops by default (invalid packets, no rule matched); every row, the locked ones included, can log to the log panel's *Logged packets*. The Service column names the services a rule matches (empty: any protocol); its search can create a new one. See [Writing firewall rules](rules.md). |
| | Services | What the rules' Service column matches: TCP, UDP or SCTP port ranges (with source ports if wanted), an ICMP or ICMPv6 type and code, or an IP protocol number. Your own next to predefined ones such as `ssh`, `dns`, `ping` or `gre`. Its Ports tab holds the port names that NAT port fields accept: built-in ones (`https`) and your own, which you add, rename and delete here. |
| | Connections | The virtual firewall's connection table (conntrack), streamed from the firewall, with each connection's start time. |
| Services | DNS | Three tabs. *DNS zones*: the zones and records the virtual firewall serves. *DNS templates*: the virtual firewall's SOA templates, DNSSEC policies and zone templates. One of the default virtual firewall (`main`) can be made *Global*: it is then shown, read-only, and usable in all virtual firewalls; a global DNS template needs a global SOA template and DNSSEC policy. A name is unique in a virtual firewall, and a global one in all. *DNS server*: the virtual firewall's DNS server (BIND), which always runs; its upstream (forwarders, the root servers, or the DNS servers from the DHCP lease on one interface, configured as BIND's forwarders; forwarding can fall back to the root servers); the interfaces it answers on; query logging, with filters, to the log panel's *DNS queries*. *New dynamic zone* (dynamic DNS) keeps the records of a zone on another nameserver in step with an interface's addresses (the WAN, say): on your own nameserver (by IP address or DNS name, looked up in the virtual firewall) by RFC 2136 dynamic update (TSIG signed), sent from the virtual firewall, or at a DNS hosting provider through its API, called from the firewall host (Bunny DNS, Cloudflare, deSEC, easyDNS, Gandi, GleSYS, GoDaddy, Hetzner DNS, Loopia, Namecheap, NameSilo, netcup, Njalla, OVHcloud, Porkbun). A provider's tokens and keys are stored on the server and never shown again; leave one empty to keep it. Its records are edited like a zone's, its nameserver or provider under *Settings*. |
| | DHCP | Two tabs. *Leases*: active leases, and the leases of the firewall's own DHCP clients. *DHCP server*: the virtual firewall's DHCP server (Kea) on or off, its domain name and lease time, and the interfaces with the prefixes of their addresses, each with a DHCP switch. Badges on an interface: *DHCP Client* (it gets its IPv4 address by DHCP), *SLAAC-C* (it takes an IPv6 address from router advertisements), *RA* (it sends router advertisements). Edit an interface for its range, gateway and DNS servers, and on IPv6 prefixes router advertisements and SLAAC. Several prefixes with DHCP on one interface form a Kea shared network: clients get addresses from all of them. |
| | WireGuard | Tunnels, road-warrior and [site-to-site](#site-to-site-wireguard) peers; generates client and site configs, and imports a wg-quick config file. |
| | Certificates | TLS certificates from Let's Encrypt, got and renewed by the firewall; see [Certificates](#certificates). |
| | Scheduled tasks | IP list downloads and commands on a cron schedule. |
| Tools | Console | A shell on the firewall as the agent's `console_user`, in the network namespace of the selected virtual firewall (so `ip addr`, `nft list ruleset` and `ping` see that virtual firewall). *Open in window* (or the square terminal icon) opens one in a window of its own for that virtual firewall. |
| | Packet capture | Live capture with Wireshark in the browser. tcpdump runs on an interface of the selected virtual firewall (or *any*), with a capture filter (pcap syntax) and limits (packets, seconds, bytes per packet); the packets stream in as they are captured, into a packet list with Wireshark's display filters (`dns \|\| tcp.port == 443`), protocol tree and bytes. *Follow* keeps the newest packet in view. *pcap* downloads the capture for Wireshark. *Open in window* runs the capture in a window of its own, for the selected virtual firewall, so it keeps going while you use the rest of the GUI; each window is a capture of its own. The stream from the agent is capped at the rate under *Settings* (1000 kbit/s by default); when traffic outruns it, the firewall drops captured packets rather than fall behind. The agent's own API connection is left out, and at most two captures run at once. Wireshark (Wiregasm, about 20 MB) loads when the page opens; it ships with portitor-web, under its own licence (GPL-2.0-or-later, `/wiregasm/LICENSE`). |
| | Traceroute | A traceroute like MTR, run on the firewall in the selected virtual firewall with `mtr`. Pick a *source interface* (*None*, the default, lets the routing table decide) and a *destination*: an IPv4 or IPv6 address, a named host or a DNS name, which the firewall resolves (for a name with both, *IP version* picks; IPv4 by default). One probe per hop goes out each second for the given rounds (10 by default); each hop's row shows its address, loss, sent and the last, average, best and worst round trip and its standard deviation, updated as replies come. *Stop* ends it early. |
| Admin | Updates | Debian package upgrades, Portitor releases, reboot. See [Installer ISO and updates](appliance.md#updates). |
| | Settings → General | The GUI's certificate, default auto-rollback, packet capture rate, [backup and restore](#backup-and-restore). |
| | Firewalls | The hosts Portitor deploys to, each with its agent (URL, token, fingerprint). Each firewall's host is a virtual firewall named after it; the others are put on a firewall in their form, and a task runs on one. A commit deploys to every firewall whose configuration changed; with several, each waits for confirmation and they are confirmed together, and when one fails the others are rolled back at once. A link joins virtual firewalls on the same firewall. **HA**: a firewall created as the *HA secondary* of another runs its virtual firewalls too, with its own addresses (*HA peer addresses* on the interfaces), VRRP priority (*HA peer priority*, 10 below by default) and router ids where they are set; both get every commit, and VRRP decides which forwards. Each host stays active only while it hears the other or holds portitor-web's vote (the witness); otherwise it fences itself: its VRRP routers shut down and it serves no DHCP or router advertisements. A commit while one host is unreachable goes to the other, and the first catches up when it is back. DHCP runs on both with Kea's HA (the primary serves, the standby takes over and the leases stay in step), connections are synced with conntrackd so they live on after a failover, and DNS updates, the tunnel broker's endpoint update and ACME orders run on the active host only; the other copies its certificates every minute. A BGP neighbour on the pair itself (another virtual firewall over a link) has an *HA peer address*: its address on the secondary. They talk over each virtual firewall's DHCP interface, or else its first physical interface (or VLAN on one) with an address and an HA peer address; one with only internal links syncs nothing. On the console, `portitor show ha` shows a host's state, and `portitor request ha active` lets a host that hears neither be active (only when the other is known to be down). Set *HA URL* when the peer reaches an agent at another address than portitor-web (127.0.0.1, say); both need the agents' certificate fingerprints. See [High availability](ha.md). |
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
  all) when the virtual firewall is deleted; you can't rename or delete it by hand. The
  default virtual firewall, the host itself, has none: only global admins manage it.
- A role you make yourself grants the virtual firewalls you pick for it. Names starting with
  `vf-` are kept for the virtual firewalls' roles.
- On each virtual firewall a user gets the highest level any of their roles gives; a global
  viewer reads every virtual firewall anyway.

A **virtual firewall admin** changes their virtual firewall's interfaces (but not which physical
NICs it has: a global admin adds, renames and removes those), zones, rules, NAT,
routes, IP addresses, DNS (dynamic zones included), DHCP and WireGuard, its settings (not its
name, nor which virtual firewall is the default), captures its packets (*Tools → Packet
capture*) and **deploys** it. An
**virtual firewall viewer** reads it. Neither sees the other virtual firewalls, their status, leases,
counters or logged packets, nor the agent's log, Settings, Updates, Users or Roles.
Named hosts and prefixes, address lists, services, IP lists, tasks and links are
shared: everyone reads and uses them, a global admin changes them. DNS templates belong to
a virtual firewall, and its admin changes them; the default virtual firewall's global ones are
read-only in the others.

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

### Two-factor login

Under *My settings*, *Two-factor login* → *Set up* asks for your password, then shows
a QR code (and its key) for an authenticator app (TOTP: Google Authenticator, Aegis,
1Password and the like). It goes on only once you enter a code from the app, so a
mistyped key can't lock you out. Then it shows ten recovery codes, once: copy or
download them. Each logs you in once in place of a code. *New recovery codes*
replaces them; *Turn off* asks for your password.

An admin can require it of a user: *Require two-factor login* in the user's form. Such
a user can do nothing but set it up (they land on *My settings*), and can't turn it
off. New users start with the default under *Settings* (*Require two-factor login of
new users*); changing that leaves existing users as they are.

With it on, the login asks for a code after the password. A code is good once, and a
wrong one counts as a failed login. Users shows who has it on.

A user who has lost both phone and recovery codes: an admin opens the user and picks
*Reset 2FA* (an admin can always do this, for a managed user too), or, on the console, `sudo -u portitor portitor-web reset-2fa <user>`
(`portitor-config reset-2fa <user>` on a firewall run by portitor-config). The user
then logs in with the password alone and can set it up again; if it is required of
them, they must. A user a manager pushed
to portitor-config has the manager's two-factor login; it is set up and reset there
(a console reset on the firewall lasts until the manager's next commit).

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
  for over two minutes, so a site on a dynamic address (with a dynamic DNS zone) is found
  again.
- The config button of a site peer gives a wg-quick config for the router at the other
  site: this virtual firewall's prefixes under *Hosts & prefixes* (its interfaces' included) as its AllowedIPs, without the
  peer's own networks, and no DNS. If the other side is a Portitor too, enter the
  values there instead: its own WireGuard interface, and this firewall as a site peer
  with this side's networks.
- Allow the traffic with forward rules between the WireGuard interface (or its interface
  zone) and the LAN, in both directions as needed. NAT is not needed between sites.

## Certificates

*Services → Certificates* gets TLS certificates from Let's Encrypt (ACME). The CA
checks each domain of the certificate with one of two challenges:

- **HTTP-01**: the CA fetches a token from
  `http://<domain>/.well-known/acme-challenge/`, so every domain must reach the
  firewall from the Internet. See below.
- **DNS-01**: the firewall puts a TXT record at `_acme-challenge.<domain>`, so the
  domains need not be reachable at all: internal names, and wildcards
  (`*.example.com`), work. See [DNS-01](#dns-01).

With HTTP-01:

- Every domain must resolve (A, and AAAA if it has one) to an address of the
  certificate's *Interface*, the WAN say. A dynamic DNS zone (DNS, *New dynamic zone*)
  can keep those records.
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

### DNS-01

A DNS-01 certificate names a *DNS update client* (*Services → DNS update*) of the
same virtual firewall, whose provider (RFC 2136 or a DNS hosting provider's API)
and credentials write the TXT records, in the client's zone. Its records, interface
and switch don't matter here: a client kept only for certificates can be disabled
and have no records. While a client is used by a certificate, it can't be deleted.

- **Names in another zone (CNAME).** The record is put where
  `_acme-challenge.<domain>` leads: a CNAME there (or a chain of them) is followed,
  as the CA follows it. So the zones of your internal names need no API or
  credentials on the firewall; one CNAME per name, made once, points into a zone
  the client can write:

  ```
  _acme-challenge.nas.corp.example.com.  CNAME  nas.acme.example.net.
  _acme-challenge.corp.example.com.      CNAME  corp.acme.example.net.   ; also *.corp.example.com
  ```

  with the DNS update client's zone `acme.example.net`. Without a CNAME the name
  `_acme-challenge.<domain>` itself must be in the client's zone. A name that leads
  elsewhere fails the order with a message naming where the CNAME leads.
- The CNAMEs are looked up through the firewall host's resolvers
  (`/etc/resolv.conf`), and the CA looks them up in public DNS: both must see them.
  So must Let's Encrypt see the TXT record, so the client's zone must be public.
- A TXT value is added to the name's records and removed when the order is done,
  so `example.com` and `*.example.com`, which share `_acme-challenge.example.com`,
  can be in one certificate. The firewall waits up to 5 minutes for the zone's
  nameservers to have the record before the CA checks it.
- An RFC 2136 nameserver is reached from the virtual firewall, through its routes and
  rules, as the client's updates are; a provider's API from the firewall host.

### Imported certificates

A certificate from another CA is imported with its key: *Import certificate* on the
*Store* tab takes PEM files (the certificate, its intermediates and the private key;
one file may hold them all) or pasted PEM. The key must match the certificate; the
SANs and common name are read from it. It is written to the same directory at the
next commit, has no challenge and opens no port, and is never renewed: its state
turns *expired* once past its end. To replace it, edit it on the *Overview* tab and
paste the new certificate (and a new key, unless it reuses the old one). The key is
never shown again, and the deployment history keeps it redacted.

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

## ACME proxy

*Services → ACME proxy* is an ACME server for the hosts behind the firewall. A host
runs its usual ACME client (certbot, Caddy, Traefik, lego, acme.sh) with the proxy's
directory URL instead of Let's Encrypt's. The client proves control of a name over
the internal network with HTTP-01, and the firewall gets the certificate from Let's
Encrypt with DNS-01, through a DNS update client. Only the firewall holds the DNS
credentials, and the hosts need not be reachable from the Internet.

1. Make a DNS update client (*Services → DNS update*) whose zone holds the names'
   `_acme-challenge` records, or their CNAME targets, as for a
   [DNS-01 certificate](#dns-01).
2. Add a policy: the names (`nas.lan.example.com`, or `*.lan.example.com` for any
   name below it), the clients (prefixes, or hosts and prefixes by name; empty is
   any), and the DNS update client.
3. Turn the proxy on, pick the interfaces it answers on, and commit. Its status
   shows the directory URLs, such as `https://192.168.1.1:8555/directory`.

When a client orders a name:

- The name must be allowed from the client's address by a policy (tried in name
  order; the first that matches is used). Otherwise the order is refused.
- The firewall resolves the name in the virtual firewall (its own DNS, if the
  firewall serves it), and every address must be in that policy's clients. It then
  fetches `http://<name>/.well-known/acme-challenge/<token>` from the virtual
  firewall. It does not follow redirects, so the client must answer on port 80
  itself, as certbot's standalone and webroot modes, Caddy and Traefik do.
- As soon as the order is accepted, the firewall has Let's Encrypt check the names
  with DNS-01, while the client answers its own challenge. When the client then
  sends its CSR, Let's Encrypt reuses those checks, so the certificate comes back
  within seconds. This matters because some clients, such as Traefik and lego, wait
  only 30 seconds for it.
- The certificate is for the client's own key: the firewall never sees it. The
  client renews as usual. Let's Encrypt's rate limits apply to the names as always.

Wildcard certificates can't be ordered through the proxy, since HTTP-01 can't check
them; get those as a [DNS-01 certificate](#dns-01) on the firewall.

The proxy listens with HTTPS. Its certificate is either one of the virtual
firewall's certificates (from *Certificates*), which clients trust as they are, or a
self-signed one the firewall makes, for the serving interfaces' addresses. That one
must be downloaded from the status and given to the clients:

```sh
REQUESTS_CA_BUNDLE=/etc/ssl/acme-proxy.pem certbot certonly --standalone \
  --server https://192.168.1.1:8555/directory -d nas.lan.example.com
LEGO_CA_CERTIFICATES=/etc/ssl/acme-proxy.pem lego --server https://192.168.1.1:8555/directory ...
```

Traefik takes `LEGO_CA_CERTIFICATES` too, and Caddy takes `acme_ca_root`. The
*Issued* list shows the latest certificates, with the client, names and the error of
a failed order. The clients' ACME accounts are kept by the firewall; orders in
progress are lost when the agent restarts, and the client orders again.

## Backup and restore

*Settings → General → Backup* downloads the whole configuration database, encrypted with
a passphrase you choose (at least 10 characters). The file holds every secret (WireGuard
keys, TSIG secrets, IP list credentials, imported certificates' keys, the agent token), so keep the passphrase safe;
it cannot be recovered. The file is in [age](https://age-encryption.org) format:
`age -d portitor-….db.age > portitor.db` gives the SQLite database.

*Restore* takes such a file and its passphrase, or an unencrypted `portitor.db`. It
checks the file, upgrades a backup from an older Portitor version (a backup from a newer
version is refused), and replaces the configuration in one step. It keeps:

- the users, so you stay logged in,
- the deployment history,
- the firewalls under *Firewalls* (agent URL, token, fingerprint), so a backup restores
  onto a reinstalled firewall; a virtual firewall or task of the backup on a firewall
  this installation doesn't have goes to the first one.

Restore changes only the database. Review the changes on *Deploy* and apply them as
usual. Restore is refused while an apply waits for confirmation.

## Secrets

The agent token, WireGuard private and preshared keys, TSIG secrets, IP list
passwords and API keys, BGP neighbour passwords and OSPF MD5 keys are never sent back to the browser, with two exceptions: an
encrypted [backup](#backup-and-restore), and the config button of a WireGuard peer,
whose wg-quick config holds the peer's private key (when it was generated here) and
the preshared key. Treat that config like a password: hand it over securely and
delete the downloaded copy. Their fields are empty when
you open a form. Leave them empty to keep the stored value, or enter a new one to
replace it.

## portitor-config: a firewall's own configuration

A firewall can keep its configuration on itself, in **portitor-config** (portitor-web
run under that name, on port 8444), and be managed from a portitor-web elsewhere.
`install.py --agent HOST --config` installs it next to the agent. On the manager, give
the firewall its *portitor-config URL*, token (`/etc/portitor/manager.token` on the
firewall) and fingerprint under *Firewalls*.

- A commit on the manager pushes the virtual firewalls that changed to portitor-config
  and commits there; confirm and roll back from the manager as usual. The firewall's
  host (its default virtual firewall) is portitor-config's own: read-only on the
  manager, changed on the firewall.
- What the manager pushed is read-only on the firewall. When it can't wait, a global
  admin there uses *Break glass* on the virtual firewall to edit it; the manager's
  *Drift* section (under *Firewalls*) then shows it as changed there, to *Take* that
  version or *Overwrite* it. The next commit waits until then.
- The manager's users come along at each commit, with their memberships of the pushed
  virtual firewalls: they log in on the firewall with the same password, and are changed
  on the manager only. Local users stay, and a local user's name wins over a pushed one.
- On the firewall's console, as root:
  `sudo -u portitor portitor-config set interfaces ens19 addresses=192.168.1.1/24`,
  then `portitor-config commit --confirm 120` and `portitor-config confirm`.
  `portitor-config api GET /api/...` reads anything the GUI shows.
