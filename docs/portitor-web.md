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
| `tls_cert`, `tls_key` | | Serve HTTPS directly. Set both or neither. |
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
portitor-web createadmin <user>    # create a user, or reset a user's password
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
4. portitor-web adds the firewall's physical interfaces to the default instance `main`
   as they are configured now, and says so. Check them under *Network → Interfaces*.
5. Configure addresses, rules and services, then deploy.

## The screen

- **Instance selector** (top bar). Most pages show one instance, the one selected here.
  DNS templates, users and settings are shared by all instances.
- **Agent badge** (top bar). The generation the agent has applied; yellow if its last
  apply had an error, red if portitor-web cannot reach it.
- **Log panel** (terminal icon) opens a panel at the bottom with two tabs:
  - *Agent log*: the agent's log.
  - *Logged packets*: the packets of the rules with *Log* ticked on the Rules page, as a
    table (time, instance, chain, rule, action, interfaces, protocol, source address and
    port, destination address and port, TCP flags or ICMP type). The destination port
    shows its service name from the firewall's `/etc/services`, such as `443 (https)`.
    Every row can log, whatever its action: your rules
    log every packet they match; the locked rows (invalid packets, the auto rules of
    the services, anti-lockout, and the last row, what no rule matched) log at most 10
    packets a second. The filter keeps the rows that contain every word typed, such as
    `wan tcp 443`. The agent keeps the latest 2000 packets; they are not written to the
    kernel log.
- **Console window** (square terminal icon) opens a shell on the firewall in a separate
  window.
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
| | Dashboard | The selected instance on the firewall: interfaces, WAN lease, WireGuard peers, missing programs. |
| | Deploy | Check, preview, apply, history. |
| Network | Instances | Virtual routers. `main` is the host; others are network namespaces. |
| | Links | veth pairs between instances. |
| | Interfaces | Physical, VLAN, bridge, WireGuard interfaces; WAN DHCP client. |
| | Routes | Static routes. |
| | IP addresses | The prefix tree: prefixes, addresses, DHCP scopes, router advertisements, DNS names. |
| | Hosts & prefixes | Named addresses, usable wherever addresses are entered. |
| Firewall | Interface zones | Named groups of interfaces for rules and NAT. |
| | Rules | Input, forward and output rules, with per-rule traffic counters and counts of what each chain drops by default (invalid packets, no rule matched); every row, the locked ones included, can log to the log panel's *Logged packets*. The Service column names the services a rule matches (empty: any protocol); its search can create a new one. |
| | Services | What the rules' Service column matches: TCP, UDP or SCTP port ranges (with source ports if wanted), an ICMP or ICMPv6 type and code, or an IP protocol number. Your own next to predefined ones such as `ssh`, `dns`, `ping` or `gre`. Also lists the port names (`https`) that NAT port fields accept. |
| | NAT & port forwards | Masquerade, SNAT and DNAT. |
| | IP lists | Downloaded address lists (CrowdSec, blocklists), used as `@name` in rules. See [Blocking with CrowdSec](crowdsec.md). |
| Services | DNS zones | Zones and records served by the instance's BIND. |
| | DNS templates | SOA templates, DNSSEC policies and zone templates, shared by all instances. |
| | DHCP | Scopes (prefixes with DHCP on, set under IP addresses) and active leases. |
| | WireGuard | Tunnels, road-warrior and [site-to-site](#site-to-site-wireguard) peers; generates client and site configs. |
| | Dynamic DNS | Keeps records on an external nameserver in step with the WAN address. |
| | Scheduled tasks | IP list downloads and commands on a cron schedule. |
| Admin | Console | A shell on the firewall as the agent's `console_user`. |
| | Updates | Debian package upgrades, Portitor releases, reboot. See [Installer ISO and updates](appliance.md#updates). |
| | Settings → General | Agent connection, default auto-rollback, public WireGuard endpoint, [backup and restore](#backup-and-restore). |
| | Settings → Users | GUI users. |
| | Help | This guide and the other guides in `docs/`. |

Your own name and password are under the user menu (top right).

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
applies without confirmation. While an apply is pending, you cannot apply another one.

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
  for over two minutes, so a site on a dynamic address (with dynamic DNS) is found
  again.
- The config button of a site peer gives a wg-quick config for the router at the other
  site: this instance's prefixes under *IP addresses* as its AllowedIPs, without the
  peer's own networks, and no DNS. If the other side is a Portitor too, enter the
  values there instead: its own WireGuard interface, and this firewall as a site peer
  with this side's networks.
- Allow the traffic with forward rules between the WireGuard interface (or its interface
  zone) and the LAN, in both directions as needed. NAT is not needed between sites.

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
passwords and API keys are never sent back to the browser, except inside an encrypted
[backup](#backup-and-restore). Their fields are empty when
you open a form. Leave them empty to keep the stored value, or enter a new one to
replace it.
