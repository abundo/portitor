<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Firewall clusters

A **firewall cluster** is two firewalls that act as one. One is **active**: it
forwards the traffic and answers for the cluster's addresses. The other is the
**standby**: it has the same configuration and the same state, and takes over when
the active firewall fails. Clients keep their gateway, their DHCP leases and their
open connections through a failover.

For what to do when something fails, during maintenance, or when neither firewall is
active, see the [cluster runbook](cluster-runbook.md).

## How it works

- **One configuration.** You manage the cluster on its **primary** firewall. The
  **secondary** keeps a read-only copy of the configuration, so it can take over the
  configuration too if the primary is lost for good.
- **Every commit goes to both** firewalls. If either one fails to apply it, both
  roll it back.
- **Active and standby.** The active firewall forwards traffic and answers on the
  traffic interfaces. The standby is up and in sync, but doesn't forward or answer on
  the traffic interfaces until it takes over. Either firewall can be the active one:
  primary and secondary say where the configuration is managed, active and standby
  say which one forwards.
- **State follows.** DHCP leases, open connections and certificates are copied to
  the standby as they change.
- **Never two active firewalls.** A standby only takes over when the active firewall
  hands over, or when a third party, the **witness**, agrees. Two firewalls that
  can't reach each other never both become active.

## What you need

- **Two firewalls with the same interface names**, `ens18`, `ens19` and so on. The
  traffic interfaces (LAN, WAN, ...) are the same on both.
- **Two more interfaces on each firewall:**
  - the **cluster link**: a direct cable between the two firewalls, or a VLAN only
    they share;
  - the **management** interface, on a network of its own, with the witness. The
    firewalls' own traffic goes there too: updates, NTP and downloads.

  The cluster link and the management network must not share a failure. With one
  switch for both, losing that switch leaves no firewall active.
- **A witness** on a third machine for automatic failover: portitor-manager, on the
  management network. Without one, the primary is its own witness, and a failed
  primary needs a manual step.
- **A hardware watchdog** on each firewall. It restarts a firewall that hangs, so that
  the other can take over safely. On Proxmox VE, give each firewall VM the emulated
  Intel 6300ESB watchdog: `qm set <vmid> --watchdog model=i6300esb,action=reset`,
  then shut the VM down and start it again.
- **Hypervisors that allow changed MAC addresses** on the traffic interfaces (in
  Proxmox VE, the MAC filter off; in VMware, *forged transmits* on). Both firewalls
  use the cluster's MAC addresses.

## Setting up a cluster

Three machines, all from the [ISO](install.md):

1. **portitor-manager**, machine type *manager*, with an interface on the management
   network. Log in to it.
2. **The primary**, machine type *primary*. Besides the usual questions, it asks for
   the management interface and its address, and the cluster link. When it asks for a
   secondary string, choose *Later*.
3. **The secondary**, machine type *secondary*. It asks only for its management
   interface and address, and its cluster link. Ignore the secondary string it shows
   at the end.
4. **In portitor-manager:** *Add firewall cluster*. Give the cluster a name and leave
   *Witness* on.
5. In its form, *Add* the primary: its address and the SSH login `portitor` with its
   password. Compare the SSH host key shown with the primary's, and confirm it.
6. *Add* the secondary the same way, at its management address. portitor-manager
   then asks for the primary's login too.

portitor-manager then joins the two firewalls into a cluster, commits it, and becomes
its witness. You copy nothing by hand.

Log in with the **primary's** users, on either firewall or through
portitor-manager. Configure the cluster on the primary only.

Then, on the primary, under *Admin → Firewalls*: check that the cluster **can fail
over** (all checks green), and click **Test switchover**. It moves the traffic to the
standby and back, and reports how long each move took.

### Without portitor-manager

1. Install the primary and the secondary as above.
2. Copy the **secondary string** that the secondary shows at the end (`sudo
   portitor-setup --show-join` shows it again). It holds a secret: keep it to
   yourself.
3. Paste it into the primary's setup, or run `sudo portitor-setup --join` on the
   primary and paste it there. This adds the secondary and commits the cluster.
4. The witness is then the primary itself. For automatic failover, set up an
   external witness later (see [The witness](#the-witness)).

## Interfaces in a cluster

Under *Network → Interfaces* on the primary:

- The **cluster link** has the cluster role *Cluster link* and no address.
- The **management** interface has the cluster role *Management*, its address, and
  under *Cluster peer addresses* the secondary's address in the same network. Its
  *Management gateway* is what the standby uses for its own traffic: a router on
  the management network, or `peer` to go through the active firewall.
- **Traffic interfaces** have the same addresses on both firewalls. *Cluster monitor*
  (on by default) watches an interface's link: when the standby has more watched
  links up than the active firewall, it takes over. Turn it off for an interface
  where a failover wouldn't help.

## Watching the cluster

*Admin → Firewalls* on the primary shows each firewall's state, and whether the
cluster **can fail over now**:

| Check | Red: a failover would fail | Amber: works, with less margin |
|---|---|---|
| Active firewall | No firewall is active. | |
| Standby | The standby doesn't answer, or is fenced. | It has fewer watched links up. |
| Heartbeat paths | The firewalls can't reach each other. | One of the cluster link and management is down. |
| Witness | | The primary is its own witness, or the witness hasn't been heard lately. |
| Watchdog | A firewall has none. | A firewall has only a software watchdog. |
| Configuration | The secondary doesn't have the latest configuration. | Its copy is old. |
| Release | | The firewalls run different releases. |

**Check cluster** asks both firewalls right away, and also checks that both have the
same interfaces. Any red check means the cluster can't fail over now: fix it before
you need it.

On either firewall's console, `sudo portitor show cluster` shows the same.

## Switching over

*Switch over* on a firewall's form under *Admin → Firewalls*, or `sudo portitor
request cluster switchover` on the active firewall, moves the traffic to the standby.
Clients lose a packet or two.

**The primary takes over again** (on by default): after a failover, when the primary
is back and healthy for 30 seconds, the traffic moves back to it. Turn it off on the
primary's form under *Admin → Firewalls* to leave the traffic where it is.

## The witness

The witness is the third vote: a standby needs it to take over when it can't reach
the active firewall. A cluster has exactly one witness.

- **External** (recommended): portitor-manager on a third machine on the management
  network. When it set up the cluster, it already is the witness. To set it up by
  hand: on the primary, set *Cluster witness* to *External* under *Admin →
  Firewalls* and commit, copy the *Witness string*, and add it in portitor-manager
  under *Cluster witness*.
- **The primary itself** (the default without portitor-manager): no third machine is
  needed, but the witness goes down with the primary. When the primary fails, the
  secondary doesn't take over by itself. See the
  [cluster runbook](cluster-runbook.md).

## Updates

Update the secondary first, then the primary. Each firewall hands over before it
restarts. See [Updates](updates.md#updating-a-firewall-cluster).

## Promoting the secondary

When the primary is lost for good, **promote** the secondary: its copy of the
configuration becomes the cluster's, and it becomes the primary.

- In the secondary's GUI: click the *Cluster secondary* badge in the top bar, then
  *Promote*. Or on its console: `sudo -u portitor portitor-config promote`.
- Promoting is refused while the secondary can still reach the primary. *Force*
  promotes anyway: only use it when you are sure the old primary is off.

If the old primary comes back, it sees that it was replaced. It stays out of the way
until it has caught up, and then it serves as the new secondary. To replace it
instead, delete it under *Admin → Firewalls* and add a new secondary.

Lost with the primary: changes made on it that the secondary hadn't copied yet.
*Admin → Firewalls* shows when the secondary's copy is behind.
