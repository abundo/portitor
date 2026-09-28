<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Portitor

*Portitor* was a Roman customs officer who inspected everything that passed
through a port. The name is also a pun on network ports.

a web gui for a linux nftables firewall.
supports DNS server, DHCP server and Wireguard tunnels
DHCP client for upstream/WAN link
main use cause is residential/home user

web gui should not run on the firewall for maxiumum security. the firewall should have a daemon running, which the web gui/backend uses to get things done on the firewall

support for virtual instances (routing, firewall rules, DHCP, DNS etc) with optional internal links between them

ip prefix/addresses are handled by a hierarchical tree

## How it fits together

```
 browser ──► portitor-web (Vue GUI + REST API, PostgreSQL)      runs anywhere but the firewall
                  │  HTTPS, bearer token, pinned certificate
                  ▼
             portitor-agent (root daemon)                         runs on the firewall
                  ├─ nftables       one ruleset per instance
                  ├─ ip / netns     interfaces, VLANs, bridges, routes, veth links
                  ├─ WireGuard      wg syncconf
                  ├─ DHCP client    in-process, for the WAN
                  ├─ dnsmgr2        BIND zones + Kea DHCPv4 scopes, one pair per instance
                  └─ Kea DHCPv6, radvd   IPv6 addresses and router advertisements, per instance
```

- **portitor-web** holds the configuration in PostgreSQL. On *Deploy* it builds a
  complete desired-state document (`internal/fwconfig`) and sends it to the agent.
- **portitor-agent** validates the document again, renders every config file
  (`internal/render`) and makes the system match. It never reads the web database.
- **Instances** are virtual routers. The default instance is the host itself; every
  other instance is a Linux network namespace (`fw-<name>`) with its own interfaces,
  routing table, nftables ruleset, BIND and Kea. **Links** are veth pairs between
  instances.
- **IP addresses** live in a prefix tree per instance. Nesting follows from CIDR
  containment. An address assigned to an interface is configured on it, with the
  prefix length of the smallest enclosing prefix. A prefix with DHCP on becomes a Kea
  scope (DHCPv4 or DHCPv6). An IPv6 prefix can send router advertisements (radvd),
  optionally with SLAAC; DHCPv6 needs them. An address with a DNS name gets an
  A/AAAA record (PTR generated), and with a MAC also a fixed lease.
- **Hosts & prefixes** are named addresses. A name can be used wherever addresses are
  entered (rules, NAT, routes, DNS, DHCP, WireGuard); portitor-web expands it when it
  builds the document. A host may have an IPv4 and an IPv6 address: a rule with
  addresses of both versions is rendered as one nftables rule per version, and a
  port forward to such a host as one DNAT per version.

## Safety

- **Commit-confirm.** After *Apply*, the agent rolls back to the previous
  configuration unless the change is confirmed within the timeout (default 120 s).
  If a rule cuts off the GUI, waiting is enough. An unconfirmed change is also rolled
  back if the agent restarts.
- **Anti-lockout.** The agent always accepts its API port from `allow_from`,
  whatever rules are deployed.
- **Atomic rulesets.** Each ruleset is checked with `nft -c` before anything changes,
  and loaded as a single transaction. A failed apply restores the previous
  configuration.
- **Default deny.** Input and forward chains drop unless a rule accepts. Established/related traffic, ICMP errors, IPv6 neighbour discovery and the
  services you enable (DHCP, DNS, WireGuard ports, the WAN DHCP client) are opened
  automatically.
- **Agent API.** TLS 1.3 only, bearer token (constant-time compare), client address
  allowlist. portitor-web pins the agent's self-signed certificate by SHA-256
  fingerprint.
- **Untrusted input.** Every name, address and comment is validated on both sides
  before it reaches an nftables, BIND, Kea or WireGuard file.
- **GUI.** bcrypt passwords, login rate limiting, HttpOnly SameSite=Strict session
  cookie, JSON-only mutating requests (CSRF), strict CSP. Private keys are never sent
  to the browser, except a generated WireGuard client config.

## Install

`install.py` installs and updates both parts from a GitHub release (SHA-256
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
or netplan; the agent manages their addresses and routes.

On the **management host**, with PostgreSQL:

```sh
make install-web                            # embedded frontend
$EDITOR /etc/portitor/web.yaml              # database, jwt_secret
portitor-web migrate
portitor-web createadmin admin
systemctl enable --now portitor-web
```

Then open the GUI. Enter the agent URL, token and fingerprint under *Settings*,
configure the default instance `main` (created on first start), and deploy.

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
