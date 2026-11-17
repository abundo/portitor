<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Using the GUI

Every firewall has its own GUI, served by the firewall itself at
`https://<LAN address>/`. Nothing outside the firewall is needed to change it. To
manage several firewalls from one place, see [portitor-manager](portitor-manager.md).

## The screen

- **Firewall and virtual firewall** (top bar): most pages show one virtual firewall,
  the one picked here. The firewall itself is the first one in the list.
- **Agent badge** (top bar): the configuration the firewall runs. It turns yellow when
  the last change had an error, and red when the GUI can't reach the firewall's
  services.
- **Cluster badge** (top bar, in a firewall cluster): *Cluster primary* is where the
  configuration is managed; *Cluster secondary* is a read-only copy. See
  [Firewall clusters](cluster.md).
- **Log panel** (terminal icon): the firewall's log, the packets of the rules you set
  to log, and DNS queries.
- **Console window** (square terminal icon): a shell on the firewall, in a window of
  its own.
- **Changes banner** (blue): there are changes that aren't committed yet. *Review*
  opens *Deploy*, *Commit* applies them, and *Revert* throws them away.
- **Confirm banner** (yellow): a commit is waiting for you to confirm it.

## The menu

| Section | What is there |
|---|---|
| **Dashboard** | The firewall's health, traffic, services, VPN peers and release notes. |
| **Deploy** | Check, preview and commit changes; the history of every commit. |
| **Network** | Interfaces, interface zones, neighbours, hosts and prefixes. |
| **Routing** | Static routes and the routing tables; policy routing, VRFs and the routing protocols (BGP, OSPF, IS-IS, VRRP, BFD). |
| **Firewall** | Rules, services, rate limits, options and the connection table. |
| **Services** | DHCP, DNS, certificates, NTP, SNMP, syslog and scheduled tasks. |
| **VPN** | WireGuard and OpenVPN. |
| **Tools** | Connectivity tests, traceroute, iperf3, the console and packet capture. |
| **Admin** | Settings, firewalls and clusters, updates, backup and restore, users and roles. |
| **Help** | These guides. |

## Committing changes

Edits are saved, but nothing changes on the firewall until you commit.

On *Deploy*:

1. The configuration is checked as a whole. Problems listed at the top must be fixed
   before you can commit.
2. *Preview* shows exactly what will change on the firewall.
3. *Commit* applies the change. Its log is shown below.

**Auto-rollback.** After a commit the yellow banner counts down. Click *Confirm* to
keep the change. If you do nothing, the firewall goes back to the configuration it
ran before when the time runs out. So if a change locks you out, just wait. The
default time is set under *Settings*; the field on *Deploy* overrides it for one
commit. Only one commit can wait for confirmation at a time.

*History* lists every commit, with who made it and what happened to it.

## Users and roles

A user's own role is **admin**, **viewer** or **none**.

- An **admin** can do everything: manage users, commit, open the console, download
  a backup (with every secret in it), update and restart the firewall. Give this role
  only to someone you would trust with the whole machine.
- A **viewer** can read everything except secrets, and change nothing but their own
  name and password.
- **None** gives no access of its own, only what the user's roles grant.

**Roles** (*Admin → Directory*) grant users access to virtual firewalls, as an admin
or a viewer of each. Every virtual firewall has a role of its own, `vf-<name>`. A
virtual firewall admin changes and commits their virtual firewall, and sees nothing
of the others. Shared objects (named hosts and prefixes, address lists, services, IP
lists) are read by everyone and changed by global admins.

An admin resets another user's password from the user's form. Your own password and
name are under the user menu, top right.

Users can also come from your OpenLDAP or Active Directory servers: see
[Directory](directory.md).

## Two-factor login

Under *My settings*, *Two-factor login* → *Set up*: scan the QR code with an
authenticator app (Google Authenticator, Aegis, 1Password and the like) and enter a
code from it. Then copy or download the ten recovery codes it shows, once. Each logs
you in once in place of a code.

An admin can require two-factor login of a user, and set it as the default for new
users under *Settings*. A user who has lost both the app and the recovery codes: an
admin opens the user and chooses *Reset 2FA*.

## Sessions

A login lasts 12 hours, or 30 days with *Remember me*. Changing your password ends
your other sessions. Deleting a user, changing their role or resetting their password
ends theirs. *Log out* ends the session in that browser only; to end every session of
a user at once, change their password.

## Secrets

Keys and passwords in the configuration (VPN keys, certificate keys, passwords for
other servers) are never shown again once saved. Their fields are empty when you open
a form: leave them empty to keep the saved value, or enter a new one to replace it.

Two things do hold secrets: an encrypted [backup](backup.md), and a WireGuard
peer's config file, which holds the peer's private key. Treat that file like a
password.

## Virtual firewalls

A virtual firewall is a firewall of its own on the same machine, with its own
interfaces, routing, rules and services. The firewall itself is the first one. Add
more under *Globals → Virtual firewalls*, and join them with *Links*.

A virtual firewall moves to another Portitor firewall as a bundle: *Export* on one,
*Import* on the other. A bundle holds the virtual firewall's secrets, so only global
admins can export and import it.

## The configuration CLI

Everything in the GUI can also be done in a command-line interface, over SSH or on
the console. See [Command line and NETCONF](cli.md).

## On the console

On the firewall, as the user `portitor` (or with `sudo -u portitor` as another user):

```
portitor-config createadmin <user>    # make a GUI admin, or reset a user's password
portitor-config reset-2fa <user>      # turn off a user's two-factor login
portitor-config fingerprint           # the GUI certificate's fingerprint
portitor-config cli                   # the configuration CLI
portitor-config commit --confirm 120  # commit from the console; then portitor-config confirm
```

## Configuration file

`/etc/portitor/config.yaml` holds what the GUI needs to start. The ISO's setup writes
it; change it only when you know you need to, and restart with `sudo systemctl
restart portitor-config`.

| Key | |
|---|---|
| `bind` | The address and port the GUI listens on. |
| `tls_cert`, `tls_key` | The GUI's own certificate. A certificate chosen under *Settings* takes its place in browsers. |
| `trusted_proxies` | Addresses whose forwarded client address is believed: portitor-manager's. The login limits then count each user's own address. |
| `jwt_secret` | Signs the login sessions. Changing it ends every session. |

