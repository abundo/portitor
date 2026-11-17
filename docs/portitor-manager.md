<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# portitor-manager

**portitor-manager** manages several firewalls and firewall clusters from one place.
It runs on a machine of its own, and is optional: every firewall keeps its own
configuration and its own GUI, and works the same without it.

What it does today:

- **One place for the GUIs.** It lists your firewalls and clusters, shows whether
  each one answers, and opens each one's GUI in a tab. A cluster is listed once, and
  is opened on whichever firewall is the primary now.
- **The witness of firewall clusters.** It is the third vote that lets a cluster fail
  over by itself. See [Firewall clusters](cluster.md#the-witness).
- **Updates.** `install.py` on the manager's machine updates every firewall it
  manages, and then the manager itself.

portitor-manager has its own users. Each firewall still asks for its own login when
you open it, and its own users and roles apply there. If portitor-manager is down,
open each firewall's GUI directly: nothing about the firewalls changes.

## Installing

From the [ISO](install.md), with the machine type *manager*. The setup asks for:

- the interface that reaches the firewalls, with DHCP or a static address;
- optionally a second interface, where users reach portitor-manager;
- the DNS servers, the time zone, and the password for the console user `portitor`.

The user `portitor` can then log in to portitor-manager with the same password.

On an existing Debian 13 machine: `./install.py --manager` from a release, then
`sudo -u portitor portitor-manager createadmin <user>`.

## Adding a firewall

*Firewalls*, *Add firewall*:

1. Enter the firewall's address and an SSH login: the user `portitor` and its password
   on a firewall from the ISO.
2. portitor-manager shows the firewall's SSH host key. Compare it with the firewall's
   own, and confirm it.
3. It logs in once, reads what it needs to reach the firewall's GUI safely, and logs
   out again. The SSH password isn't kept.
4. Give the firewall a name, and add it.

**From the firewall's setup:** a firewall installed as *managed* shows a **manager
string** at the end of its setup (`sudo portitor-setup --show-join` shows it again).
On the manager's machine, run `sudo portitor-setup --join` and paste it.

## Adding a firewall cluster

*Firewalls*, *Add firewall cluster*: give the cluster a name, then *Add* its primary
and its secondary as above. When both are added, portitor-manager sets up the cluster
and becomes its witness. See [Setting up a cluster](cluster.md#setting-up-a-cluster).

## The cluster witness page

*Cluster witness* lists the clusters this portitor-manager is the witness of. Clusters
set up from *Add firewall cluster* are added for you. For a cluster set up another
way, copy the *Witness string* from the cluster's primary (*Admin → Firewalls*) and
add it here.

A cluster has exactly one witness. Don't add the same cluster to two
portitor-managers.

## Users

portitor-manager's users are its own, separate from the firewalls' users. There is
no user until you make one: the ISO makes `portitor`, and `sudo -u portitor
portitor-manager createadmin <user>` makes another user or resets a password.

## Configuration file

`/etc/portitor/manager.yaml` holds what portitor-manager needs to start:

| Key | Default | |
|---|---|---|
| `bind` | `127.0.0.1:8080` | The address and port it listens on. |
| `tls_cert`, `tls_key` | | Serve HTTPS directly. Without them, put a TLS reverse proxy in front. |
| `data_dir` | `/var/lib/portitor-manager` | Where it keeps its configuration. The files hold secrets: keep them private. |
| `ssh_listen` | | Serve the configuration CLI over SSH, for example `:2222`. |

Before 1.1.0 portitor-manager was named portitor-web, and its file was
`/etc/portitor/web.yaml`. An update moves it.

On each firewall that portitor-manager manages, add the manager's address under
`trusted_proxies` in `/etc/portitor/config.yaml`, so that the firewall's login limits
count each user's own address. A firewall installed from the ISO as *managed* already
has it.

## Commands

As the service user (`sudo -u portitor ...`) on the manager's machine:

```
portitor-manager createadmin <user>              # make a user, or reset their password
portitor-manager check                           # does each firewall answer?
portitor-manager list-firewalls                  # the firewalls it manages
portitor-manager add-witness <witness string>    # be the witness of a cluster
portitor-manager cli                             # its configuration CLI
```
