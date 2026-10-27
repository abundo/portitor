<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Deployments

Portitor runs in one of three layouts:

| | Hosts | For |
|---|---|---|
| [Everything on one host](#everything-on-one-host) | 1 | a home or a small office |
| [Firewall and portal](#firewall-and-portal) | 2 | one place for the GUIs of one or more firewalls |
| [HA pair and portal](#ha-pair-and-portal) | 3 | a firewall that keeps forwarding when a host fails (experimental) |

In every layout, each firewall keeps its own configuration. **portitor-config**, on
the firewall next to **portitor-agent**, holds the configuration, serves the GUI and
deploys to the agent. **portitor-web**, the portal, holds no configuration and has no
users. It passes each firewall's GUI through at `/fw/<name>/`, and the firewall's own
login applies (see [portitor-config and portitor-web](portitor-web.md)). If the
portal is down, you can still open each firewall's GUI directly and change it.

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
pick in the top bar switches between them. Each firewall has its own login.

- **ISO:** pick *agent* on the firewall and copy the portal string it prints at the
  end. Then pick *web* on the portal host and paste the string there
  ([Firewall and portal on separate hosts](appliance.md#firewall-and-portal-on-separate-hosts)).
  The portal string of another firewall adds that firewall to the same portal.
- **install.py:** on the portal host, `./install.py --web --agent 192.168.1.1`. Add
  each firewall under `firewalls:` in `/etc/portitor/web.yaml`, and put the portal's
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

Two firewalls run as an [HA pair](ha.md) with the same configuration, and
[VRRP](vrrp.md) decides which one forwards. The primary's portitor-config holds the
configuration and deploys to both hosts. The secondary's portitor-config keeps a
read-only copy, so it can be promoted if the primary is lost.

The third host runs portitor-web. It plays two roles:

- **The portal.** It lists both hosts. A login on either host is good on both.
- **The witness.** A host stays active only while it hears its peer or holds the
  witness's vote. With the portal as the [external witness](ha.md#the-witness),
  the secondary takes over by itself when the primary fails. Without an external
  witness, the witness is the primary's portitor-config and is lost with the
  primary. The secondary then fences itself until you promote it.

To set it up:

1. Install both firewalls as for a firewall and portal (ISO *agent*, or
   `./install.py --web --agent 192.0.2.5,192.0.2.6` from the portal host), and add
   both hosts to the portal.
2. Set up the pair in the primary's GUI ([Setting up a pair](ha.md#setting-up-a-pair)).
3. Under *Admin → Firewalls*, set *HA witness* to *External* on the primary, then
   commit. Copy the *Witness string* under `witness:` in the portal's `web.yaml`, and
   let the portal's address in through both agents' `allow_from`.

`./install.py` on the portal host updates the pair one host at a time, the secondary
first, so one host keeps forwarding.

A pair also works without a portal, and its witness can run on a host of its own
(`portitor-web witness`). Even then, the third host is what lets the secondary take
over without you.
