<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Deployments

> **Developer reference.** This was a user guide until 1.1.0; the user guides are now
> docs/install.md, docs/portitor-manager.md and docs/cluster.md. It is kept here for its implementation details (timings,
> mechanisms, file names, commands). It still uses the names of before 1.1.0:
> *portitor-web* is portitor-manager, an *HA pair* a firewall cluster, *open/closed*
> active/standby (and fenced), the *HA link* the cluster link.

Portitor runs in one of three layouts:

| | Hosts | For |
|---|---|---|
| [Everything on one host](#everything-on-one-host) | 1 | a home or a small office |
| [Firewall and portal](#firewall-and-portal) | 2 | one place for the GUIs of one or more firewalls |
| [HA pair and portal](#ha-pair-and-portal) | 3 | a firewall that keeps forwarding when a host fails (experimental) |

In every layout, each firewall keeps its own configuration. **portitor-config**, on
the firewall next to **portitor-agent**, holds the configuration, serves the GUI and
deploys to the agent. **portitor-web**, the portal, has its own login and a small
configuration of its own: which firewalls and HA firewalls it serves, and the HA
witness strings (`portal.json`). It holds no firewall configuration. It passes each
firewall's GUI through at `/fw/<name>/`, where the firewall's own login applies too
(see [portitor-config and portitor-web](portitor-web.md)). If the portal is down, you
can still open each firewall's GUI directly and change it.

## Everything on one host

```
 browser ──► firewall: portitor-config (GUI, configuration) ──► portitor-agent
```

One host runs the firewall and its GUI. Nothing else is needed.

- **ISO:** pick *both* in the first-boot setup ([Installer ISO](appliance.md)).
- **install.py:** `./install.py --agent 192.168.1.1`, run on the firewall or from
  another host over SSH (see the [README](../README.md#install)).

You open the GUI on the firewall's LAN address, port 8444. You can add a portal later
without changing the firewall's configuration.

## Firewall and portal

```
 browser ──► portal: portitor-web ──► firewall: portitor-config ──► portitor-agent
```

The firewall is the same as on one host. A second host runs portitor-web, so the GUI
is reached in one place. One portal can list several firewalls, and the *Firewall*
pick in the top bar switches between them. You log in to the portal first, then to
each firewall.

- **ISO:** pick *agent* on the firewall and copy the portal string it prints at the
  end. Then pick *web* on the portal host and paste the string there
  ([Firewall and portal on separate hosts](appliance.md#firewall-and-portal-on-separate-hosts)).
  The portal string of another firewall adds that firewall to the same portal.
- **install.py:** on the portal host, `./install.py --web --agent 192.168.1.1`. Add
  `sudo -u portitor portitor-web createadmin <user>`, log in to the portal and add each
  firewall (*Add firewall* reads its fingerprint over SSH), and put the portal's
  address in `trusted_proxies` in each firewall's `config.yaml`
  ([portitor-web](portitor-web.md#portitor-web)).

From then on, `./install.py` on the portal host updates the portal and every
firewall it lists.

## HA pair and portal

```
                          ┌──► firewall 1 (primary):   portitor-config ──► portitor-agent
 browser ──► portal ──────┤                                  │ copy of the configuration
             (witness)    └──► firewall 2 (secondary): portitor-config ──► portitor-agent
```

> **Experimental.** This layout is new and needs more testing. Try it in a lab
> before relying on it in production, and report what you find.

Two firewalls run as an [HA pair](ha.md) with the same configuration: one is active
and forwards, the other is a standby with the same addresses. The primary's portitor-config holds the
configuration and deploys to both hosts. The secondary's portitor-config keeps a
read-only copy, so it can be promoted if the primary is lost.

The third host runs portitor-web. It plays two roles:

- **The portal.** It lists the pair as one *HA firewall* and serves it from whichever
  host is primary now. A login to the pair is good on both hosts.
- **The witness.** A host opens only with the witness's vote or a handover from its
  peer. With the portal as the [external witness](ha.md#the-witness), the standby
  takes over by itself when the active host fails. Without an external witness, the
  witness is the primary's portitor-config and is lost with the primary: the secondary
  then stays closed until you open it by hand and promote it. The portal reaches the
  hosts on their management network.

To set it up:

1. Install the two firewalls (ISO *primary* and *secondary*) and the portal (ISO
   *web*). With `install.py`: `./install.py --web --agent 192.0.2.5,192.0.2.6` from
   the portal host, then `sudo -u portitor portitor-web createadmin <user>`.
2. In the portal, *Add HA firewall*: give the pair a name, then *Add* its *Primary*
   and its *Secondary* host (SSH, with the host key confirmed first). When the second
   host is added, the portal pairs them and, with *Witness* on (the default), makes
   itself the pair's external witness. You copy nothing by hand. The portal must be
   on the management network (both agents' `allow_from`). With `install.py`, also
   add the portal's address to `trusted_proxies` on both hosts.

Without the portal's help, the strings do the same. The primary adds the secondary
with `sudo portitor-setup --join`. Then set *HA witness* to *External* on the
primary, commit, and add its *Witness string* in the portal (*HA witness*, or
`portitor-web add-witness`). A portal string given to the portal's `sudo
portitor-setup --join` adds a host as a plain firewall, not as part of an HA firewall.

The commands, in order, are in [Step by step from the ISO](ha.md#step-by-step-from-the-iso).

`./install.py` on the portal host updates the pair one host at a time, the secondary
first; each host hands over before its agent restarts, so one host keeps forwarding.

A pair also works without a portal, and its witness can run on a host of its own
(`portitor-web witness`). Even then, the third host is what lets the secondary take
over without you.
