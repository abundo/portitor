<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Portitor

*Portitor* was a Roman customs officer who inspected everything that passed
through a port. The name is also a pun on network ports.

Portitor is a web GUI for a Linux nftables firewall, aimed mainly at home and small
office networks. It manages:

- firewall rules (input, forward, output) with named services, hosts and prefixes, and
  NAT: masquerade, SNAT and port forwards
- a DNS server (BIND) and a DHCP server (Kea, DHCPv4 and DHCPv6) with router
  advertisements
- WireGuard tunnels, for road warriors and site-to-site
- a DHCP client for the WAN link
- DNS update: DNS records follow the WAN addresses, on your own nameserver (RFC 2136, TSIG)
  or at a DNS hosting provider (Cloudflare, Hetzner, deSEC, Loopia, GleSYS and more, via libdns)
- certificates: Let's Encrypt (ACME, HTTP-01) certificates, renewed automatically; port 80
  opens only while a challenge is answered
- IP lists: CrowdSec decisions or downloaded blocklists, used as `@name` in rules
- scheduled tasks: download IP lists or run commands on a cron schedule
- virtual firewalls, each with its own routing, rules, DHCP and DNS, with optional
  internal links between them
- IP prefixes and addresses in a hierarchical tree (IPAM)

For the best security the GUI does not run on the firewall. A small daemon on the
firewall, the agent, makes the changes the GUI asks for. For a single box, an
[installer ISO](docs/appliance.md) puts both on the firewall.

## How it fits together

```
 browser ──► portitor-web (Vue GUI + REST API, SQLite)          runs anywhere but the firewall
                  │  HTTPS, bearer token, pinned certificate
                  ▼
             portitor-agent (root daemon)                         runs on the firewall
                  ├─ nftables       one ruleset per virtual firewall
                  ├─ ip / netns     interfaces, VLANs, bridges, routes, veth links
                  ├─ WireGuard      wg syncconf
                  ├─ DHCP client    in-process, for the WAN
                  ├─ DNS update     in-process RFC 2136 updates (ifnsupdate), provider APIs (libdns)
                  ├─ ACME           Let's Encrypt certificates (lego), HTTP-01 in the virtual firewall
                  ├─ IP lists       downloads (CrowdSec LAPI, plain text) into nftables sets
                  ├─ scheduler      cron-style tasks
                  ├─ dnsmgr2        BIND zones + Kea DHCPv4 scopes, one pair per virtual firewall
                  └─ Kea DHCPv6, radvd   IPv6 addresses and router advertisements, per virtual firewall
```

- **portitor-web** holds the configuration in an SQLite database. On *Deploy* it builds a
  complete desired-state document (`internal/fwconfig`) and sends it to the agent.
- **portitor-agent** validates the document again, renders every config file
  (`internal/render`) and makes the system match. It never reads the web database.
- **Virtual firewalls** are virtual routers. The default virtual firewall is the host itself; every
  other virtual firewall is a Linux network namespace (`fw-<name>`) with its own interfaces,
  routing table, nftables ruleset, BIND and Kea. **Links** are veth pairs between
  virtual firewalls. The default virtual firewall is not listed on the *Virtual firewalls*
  page and can't be changed or deleted. Its files are where a sysadmin expects them, run by
  the distribution's own units: `/etc/nftables.d/portitor.nft`, `/etc/wireguard/<if>.conf`,
  `/etc/bind/named.conf` (`named`), `/etc/kea/kea-dhcp4.conf` and `kea-dhcp6.conf`
  (`kea-dhcp4-server`, `kea-dhcp6-server`) and `/etc/radvd.conf` (`radvd`); a file it
  replaces is kept as `<file>.portitor-orig`. Every other virtual firewall's are under
  `/etc/portitor/instances/<name>`, run by `portitor-*@<name>` units.
- **Interfaces** carry their own addresses, IPv4 and IPv6 mixed, as many as needed,
  each with its prefix length (`192.168.1.1/24`, `fd00:1::1/64`).
- **IP addresses** live in a prefix tree per virtual firewall. Nesting follows from CIDR
  containment; the interfaces' addresses and their prefixes appear in it by
  themselves. A prefix with DHCP on becomes a Kea scope (DHCPv4 or DHCPv6) on the
  interface with an address in it; several scopes on one interface form a Kea shared
  network, so clients get addresses from all of them. An IPv6 prefix can send router
  advertisements (radvd), optionally with SLAAC; DHCPv6 needs them. An address with
  a DNS name gets an A/AAAA record (PTR generated), and with a MAC also a fixed lease.
- **IP lists** are address lists the agent downloads: the ban decisions of a CrowdSec
  Local API (as a bouncer, with its API key), or plain text with one address or prefix
  per line (a CrowdSec blocklist integration with HTTP basic auth, Spamhaus DROP, ...).
  A rule uses one as `@name` in its source or destination; it becomes a pair of
  nftables sets (`name_v4`, `name_v6`) in every virtual firewall whose rules use it, loaded in
  the same transaction as the rules. The agent downloads a list when it is first
  deployed and whenever a scheduled task says so, from the firewall host (root
  namespace); a failed download keeps the last good one, which also survives a restart.
  A download that is not a list (an HTML error page, JSON that is not a decision
  stream) counts as failed. A list is *ok* once its sets are loaded. See [docs/crowdsec.md](docs/crowdsec.md) for blocking with CrowdSec.
- **Scheduled tasks** run on the firewall on a cron schedule, in its time zone: download
  an IP list again, or run a shell command as `console_user` (off when the console is).
- **Hosts & prefixes** are named addresses. A name can be used wherever addresses are
  entered (rules, NAT, routes, DNS, DHCP, WireGuard); portitor-web expands it when it
  builds the document. A host may have an IPv4 and an IPv6 address: a rule with
  addresses of both versions is rendered as one nftables rule per version, and a
  port forward to such a host as one DNAT per version.

## Safety

- **Commit-confirm.** After *Apply*, the agent rolls back to the previous
  configuration unless the change is confirmed within the timeout (default 120 s).
  If a rule cuts off the GUI, waiting is enough. The rollback target is on disk
  before anything changes, so an unconfirmed change is also rolled back if the agent
  restarts or crashes; a rollback that fails is tried again every minute and at the
  next start. The first apply has nothing to roll back to, and a timeout of 0 turns
  confirmation off.
- **Anti-lockout.** The agent always accepts its API port and SSH (22) from `allow_from`,
  whatever rules are deployed.
- **Atomic rulesets.** Each ruleset is checked with `nft -c` before anything changes,
  and loaded as a single transaction, before the virtual firewall's interfaces come up or
  forwarding is turned on. A failed apply restores the previous configuration; if
  that fails too, the deployment says so.
- **Default deny.** All chains (input, forward, output) drop unless a rule accepts; new
  virtual firewalls start with an "allow all output" rule. Established/related traffic, ICMP
  errors, IPv6 neighbour discovery and the services you enable (DHCP, DNS, WireGuard
  ports, the WAN DHCP client) are accepted before the rules. Port forwards are
  accepted after the forward rules, so a rule can drop what a port forward would let
  in (an IP list, say). A new drop rule does not end connections that are already
  established.
- **Agent API.** TLS 1.3 only, bearer token (constant-time compare), client address
  allowlist. portitor-web pins the agent's self-signed certificate by SHA-256
  fingerprint.
- **Untrusted input.** Every name, address and comment is validated on both sides
  before it reaches an nftables, BIND, Kea or WireGuard file.
- **GUI.** bcrypt passwords, login rate limiting, HttpOnly SameSite=Strict session
  cookie, JSON-only mutating requests (CSRF), strict CSP. Private keys and TSIG
  secrets are never sent to the browser, except a generated WireGuard client config.
- **Console.** *Console* in the menu (or its own window, from the top bar) is a
  shell on the firewall that the agent runs as `console_user` in `agent.yaml`
  (default `portitor`; `none` turns it off). The shell has that user's rights,
  which on a host set up by `install.py` include sudo. portitor-web allows the
  WebSocket from its own origin only, and logs who opened it. An open console closes
  when its session expires or is revoked (password changed, user deleted). Command
  tasks run as the same user, and `none` turns them off too.

## Install

**Single box, from the ISO.** The installer ISO (amd64) installs Debian 13 with
everything on it, the GUI included. At the first boot it asks for the LAN interface,
its address and a password, then you continue in the GUI. See
[docs/appliance.md](docs/appliance.md), which also covers updating Debian and Portitor
from the GUI (*Admin → Updates*) and building the ISO (`iso/build.sh`).

**GUI on another host.** `install.py` installs and updates both parts from a GitHub release (SHA-256
verified): portitor-web on the host it runs on, portitor-agent on the firewall over
SSH as `portitor` (`--ssh-user`; a user with passwordless sudo, or root). If it
cannot log in, it prints how to create that user and its sudoers entry. Download it
from a release, then:

```sh
./install.py --web --agent 192.168.1.1      # first install: binaries, units, example configs
./install.py                                # later: pick a release; updates what is installed
./install.py --install latest --yes         # unattended update
```

On an update it restarts the agent first (it rejects document fields it does not know,
so it must not be older than the GUI), then stops portitor-web, migrates the database
and starts it again. It finds the firewall from the agent URL under *Settings*. A
systemd unit you changed is shown as a diff and kept unless you confirm. `--dry-run`
shows what would change; `--source` builds and installs a source checkout instead.

A first install creates the configs but starts nothing, and prints what is left to do.
By hand, it is:

On the **firewall** (Debian/Ubuntu shown; needs nftables, iproute2, wireguard-tools,
bind9, bind9-utils, kea-dhcp4-server, kea-dhcp6-server, radvd):

```sh
make install-agent                          # binary, systemd units, /etc/portitor/agent.yaml
portitor-agent init --host 192.168.1.1      # prints token + certificate fingerprint
$EDITOR /etc/portitor/agent.yaml            # listen address, allow_from
systemctl disable --now named kea-dhcp4-server kea-dhcp6-server radvd   # the agent runs its own per-instance units
systemctl enable --now portitor-agent
```

Take the interfaces you hand to the firewall away from NetworkManager, systemd-networkd
or netplan; the agent manages their addresses and routes. This matters most for a WAN
interface in DHCP mode: with a second DHCP client on the same MAC address the ISP often
answers only that one, and the agent logs `unable to receive an offer` and names the
address the other client set. On Ubuntu the installer writes a netplan file with
`dhcp4: true` for the interface. From the console (the interface loses its address),
remove the interface from `/etc/netplan/*.yaml`, then:

```sh
netplan apply
ip addr flush dev ens18 scope global        # networkd may leave its address and route
ip route del default dev ens18 proto dhcp
```

Keep netplan entries for interfaces the firewall does not manage (a separate management
port, say).

An empty netplan config is not always enough. Check which file systemd-networkd uses:

```sh
networkctl status ens18        # "Network File:"; "unmanaged" is what you want
```

On Ubuntu releases whose initramfs is built by dracut, `Network File:` can be
`/run/systemd/network/zzzz-dracut-default.network`: dracut's catch-all, with DHCP
(IPv4 and IPv6) on every interface, written at every boot. Besides the DHCP lease it
takes the DHCPv6 client port, so the agent's DHCPv6 client reports `bind: address
already in use (systemd-network holds the DHCPv6 client port 546 ...)`. Mark the
firewall's interfaces unmanaged in a file that sorts before it (networkd uses the
first matching file):

```sh
cat >/etc/systemd/network/10-portitor-unmanaged.network <<'EOF'
# The Portitor agent configures these interfaces.
[Match]
Name=ens18 ens19

[Link]
Unmanaged=yes
EOF
networkctl reload
ip addr flush dev ens18 scope global
ip route del default dev ens18 proto dhcp
```

List every interface the firewall manages under `Name=` (space separated; globs such
as `ens*` work), and leave out a management port that networkd should keep.
The installer ISO does not need this: it is Debian with ifupdown, and neither
netplan nor dracut is installed.

When portitor-web reaches the agent, it adds the firewall's physical interfaces it
has not seen before to the default virtual firewall, as they are configured at that moment
(link state and static addresses), so a first deploy leaves them as they are. An
interface you delete is not added again. Physical interfaces in the configuration
that the firewall does not have are shown as a warning.

On the **management host**, with a system user `portitor`:

```sh
make install-web                            # embedded frontend
$EDITOR /etc/portitor/web.yaml              # jwt_secret
install -d -o portitor -g portitor -m 0700 /var/lib/portitor-web
sudo -u portitor portitor-web migrate
sudo -u portitor portitor-web createadmin admin
systemctl enable --now portitor-web
```

Run portitor-web commands as `portitor`, so the database files SQLite creates stay
writable for the service; as root it refuses.

portitor-web listens on `127.0.0.1:8080` and its session cookie needs HTTPS: set
`tls_cert` and `tls_key` in `web.yaml`, or put a TLS reverse proxy in front (see
[Configuration](docs/portitor-web.md#configuration)).

Then open the GUI. Enter the agent URL, token and fingerprint under *Settings*,
configure the default virtual firewall `main` (created on first start), and deploy.
[docs/portitor-web.md](docs/portitor-web.md) describes the configuration file, the
commands and the GUI.

## Not yet supported

A DHCPv6 client and prefix delegation on the WAN (IPv6 on the WAN is SLAAC only, so LAN
prefixes are static), PPPoE, and a boot-time ruleset in place before the agent starts.

See [DEV.md](DEV.md) for development and [AGENTS.md](AGENTS.md) for the code layout.

## Licence

Copyright 2026 The Portitor contributors.

Portitor is free software: you can redistribute it and/or modify it under the terms of
the GNU Affero General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version. See
[LICENSE](LICENSE). If you run a modified Portitor that others use over a network, the
AGPL requires you to offer them its source.

Contributions are accepted under a Developer Certificate of Origin (`git commit -s`),
not a CLA; see [CONTRIBUTING.md](CONTRIBUTING.md).
