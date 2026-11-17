<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[Report a vulnerability](https://github.com/abundo/portitor/security/advisories/new).
Do not open a public issue.

Include what you can of:

- the affected component (`portitor-config`, `portitor-agent`, `portitor-manager`, `install.py`, the installer ISO) and version
  (shown in the GUI's top bar),
- steps to reproduce, or a proof of concept,
- the impact as you see it.

You will get an answer as soon as possible. Fixes are released as a new version, and
the advisory is published once a release is available.

## Supported versions

Only the latest release gets security fixes. Update with `install.py`.

## Scope

Portitor is a firewall, so we are especially interested in:

- anything that lets traffic through that the deployed rules should drop,
- ways around commit-confirm or the anti-lockout rule,
- unauthenticated or unauthorised access to the agent API or the web GUI,
- input that reaches an nftables, BIND, DHCP server or WireGuard file without being
  validated,
- secrets (WireGuard keys, agent token, password hashes) leaking to the browser or
  into deployment history.

## Security model

**On the firewall.** portitor-config (the GUI, REST API, CLI over SSH and NETCONF)
keeps the configuration in files in its data directory and runs as the unprivileged
user `portitor`. The agent runs as root and makes the changes. portitor-config
reaches the agent over HTTPS with a bearer token (`/etc/portitor/agent.token`, root
only) and the agent's pinned certificate. The agent checks every document it gets
again, whoever sent it.

- On a single firewall the agent listens on 127.0.0.1 only. The API does not tell
  local users apart: any process that can read the token, or run as `portitor`
  (which can read the data directory with every secret in it), can reconfigure the
  firewall. Treat local accounts on a firewall as administrators.
- In a firewall cluster the agent also listens on the management network, limited by
  `allow_from`. Its clients there are the other firewall's portitor-config (with the
  token) and its peer agent and the witness. Those two use the cluster's or the
  witness's secret, which opens only the cluster routes (heartbeats, votes, DHCP lease
  copies), not configuration.
- `allow_from` also gets an always-on accept rule for the agent's port, SSH and
  portitor-config's port (anti-lockout). Keep it to the management network, never
  the WAN.

**GUI users and roles.** portitor-config's users are global **admins**, **viewers**
or **none**. Roles also grant virtual firewalls one at a time, at admin or viewer
level. A global admin can do everything, including open a root-capable console,
download a backup with every secret in it and update the firewall: give that role
only to someone you would give root. Viewers can't change anything, and they don't see
private keys. A virtual firewall admin changes and deploys their own virtual firewalls
only. Secrets are never sent to the browser, except in the downloads that exist to
carry them (an encrypted backup, a WireGuard or OpenVPN client config). Users can log
in through LDAP or Active Directory, and two-factor login is available. See
[Users and roles](docs/gui.md#users-and-roles).

**portitor-manager, optional.** It runs on a host of its own, with its own
users and configuration in its data directory (`portal.json`: the firewalls' URLs and
certificate fingerprints, the cluster witness strings, the users' password hashes). Keep it
private. Every portitor-manager user has full access to it. Behind it, each firewall
still asks for its own login (a firewall cluster shares one login across both firewalls). portitor-manager
pins each firewall's certificate. It holds no agent tokens and no firewall
configuration. SSH credentials used to add a firewall are used for that connection
only, and the host key is confirmed first. A witness string lets portitor-manager vote in
its cluster's failover. It does not let it change configuration. On each
firewall, list portitor-manager in `trusted_proxies` only, so that no other host can pick
the client address the login limits count.

Neither portitor-config nor portitor-manager is meant to be exposed to the internet. See
[Safety](README.md#safety) for the protections on the firewall itself.
