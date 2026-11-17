<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Cluster runbook

What to expect, and what to do, when something happens to a firewall cluster. How a
cluster works and how to set one up is in [Firewall clusters](cluster.md).

## States

| State | What the firewall does |
|---|---|
| **Active** | Forwards the traffic and answers for the cluster's addresses. |
| **Standby** | Up and in sync, ready to take over. Doesn't forward or answer on the traffic interfaces. |
| **Fenced** | Can reach neither the other firewall nor the witness. It doesn't forward, and won't take over on its own, because it can't tell whether the other firewall is still active. |
| **Stale** | An old primary that was replaced by a promotion. It doesn't forward until the new primary has caught it up as its secondary. |

**Primary** and **secondary** say where the configuration is managed: you make changes
on the primary, and the secondary's GUI is a read-only copy. They don't say which one
forwards: either one can be active.

## Where to look

- **GUI:** *Admin → Firewalls* on the primary. The *Cluster* column shows each
  firewall's state. Under the firewalls, the cluster shows whether it **can fail over**
  now, as green, amber and red checks. *Check cluster* asks both firewalls right away.
- **Console:** `sudo portitor show cluster` on either firewall shows its state, the
  other firewall, the witness's vote, the watched links and the watchdog.
- **Logs:** `sudo journalctl -u portitor-agent -n 200` on the firewalls.

A red check means the cluster would not fail over now. Fix it before you need it.

## A firewall fails

**What happens:** if the active firewall loses power, crashes or hangs, the standby
becomes active within about 6 seconds, with the witness's agreement. A firewall that
hangs is restarted by its watchdog, and comes back as the standby. Clients keep their
gateway, their DHCP leases and their connections through the cluster. SSH sessions to
the firewall itself are cut.

If the standby fails, traffic isn't affected. The *Standby* check turns red.

**What you do:**

1. Bring the failed firewall back: power it on, or repair it. It comes back as the
   standby.
2. If it was the **primary**, the traffic moves back to it after it has been up and
   healthy for 30 seconds (*Primary takes over again*, on by default). While the
   primary is down, the configuration can't be changed: the secondary's GUI is
   read-only.
3. If the primary is **gone for good** (broken hardware, a lost site),
   [promote the secondary](cluster.md#promoting-the-secondary). Changes the secondary
   hadn't copied yet are lost.

**Without an external witness** (the primary is its own witness), the secondary does
**not** take over when the primary fails, because the witness failed with it. Traffic
stops until you make the secondary active by hand: follow
[No firewall active](#no-firewall-active-safe-manual-recovery).

## The witness fails

**What happens:** nothing, as long as the two firewalls can reach each other. The
*Witness* check turns amber.

**The risk:** without the witness the standby can't take over. If the active firewall
fails too, no firewall is active and traffic stops.

**What you do:** bring the witness back soon (`sudo systemctl status portitor-manager`
on its machine). It resumes by itself; there is nothing to do on the firewalls.

## A network link breaks

The firewalls reach each other over two paths: the **cluster link** and the
**management** network.

| What breaks | What happens | What you do |
|---|---|---|
| The cluster link only | The firewalls reach each other over management. Traffic isn't affected. Open connections are no longer copied, so a failover now would drop them. *Heartbeat paths* turns amber. | Fix the cable or VLAN. |
| The management network only | The firewalls reach each other over the cluster link. Traffic isn't affected. The witness, the GUI and the firewalls' own updates and downloads are unreachable. | Fix the management network. |
| Both, at the active firewall only | The active firewall can't keep its vote and stops forwarding. The standby gets the witness's vote and becomes active. | Fix the links. The firewall comes back as the standby. |
| Both, between the firewalls (for example one switch carries both) | The active firewall stops forwarding, and the standby can't reach the witness. **No firewall is active**, and traffic stops. | Restore either link: the cluster recovers by itself within seconds. If you can't, follow [No firewall active](#no-firewall-active-safe-manual-recovery). |
| A watched traffic link on the active firewall | If the standby has more watched links up for 2 seconds, the active firewall hands over in about 3 seconds. Connections survive. | Fix the link. Such handovers happen at most once a minute, so a flapping link can't bounce the traffic back and forth. |

If the cluster link and the management network go through the same switch, one
switch failure stops the whole cluster. *Check cluster* warns about this when it sees
a switch on the cluster link.

## Rebooting a firewall for maintenance

A clean shutdown or reboot hands over: the standby becomes active at once. Clients
lose a packet or two.

1. Under *Admin → Firewalls*, check that the cluster **can fail over** (no red checks).
2. **Do the standby first.** Reboot it, patch it, or shut it down. Traffic isn't
   affected. Wait until it shows *standby* again and the checks are green.
3. **Then the active firewall.** Reboot it (it hands over on the way down), or move
   the traffic first with *Switch over* on its form, or `sudo portitor request cluster
   switchover` on its console.
4. When it comes back:
   - The primary takes the traffic back after 30 seconds (by default).
   - The secondary stays the standby. Use *Switch over* if you want the traffic on it.

**Updates** follow the same order: secondary first, then primary. See
[Updates](updates.md#updating-a-firewall-cluster).

**Configuration changes** are made on the primary. They wait while the primary is
down.

## No firewall active: safe manual recovery

Both firewalls show *fenced* (or one is fenced and the other is down), and no traffic
passes. The cluster is doing what it was designed to do: neither firewall can tell
whether the other one is still active, so neither takes over. **Two active firewalls
would both answer for the same IP and MAC addresses**, which is worse than an outage.
So before you make a firewall active by hand, make sure the other one can't forward
traffic.

1. **Try the easy fix first.** Restore the cluster link, the management network or
   the witness if you can. The cluster then recovers by itself within seconds.
2. **Choose the firewall to make active.** Pick the one that is healthy and has its
   traffic links up. If one firewall is broken, the other one is your choice.
3. **Make sure the other firewall is off.** Use its hypervisor or out-of-band console,
   or pull its power or its traffic cables. Not being able to reach a firewall
   doesn't prove it is down: it may only be cut off from you.
4. **Make the chosen firewall active.** On its console:

   ```
   sudo portitor request cluster active --minutes 240
   ```

   It becomes active within a few seconds, and the command is logged. It stays active
   for the minutes you give, at most 24 hours. When the time runs out, it stops
   forwarding again unless it can reach the other firewall or the witness by then.
   Run the command again before the time is up if the repair takes longer.
5. **Check:** `sudo portitor show cluster` shows *active*, and clients reach the
   Internet.
6. **Repair**, then bring the other firewall back with its links working. It sees an
   active firewall, and becomes the standby. Check under *Admin → Firewalls* that the
   cluster can fail over again.
7. **If the active firewall is the secondary and the primary won't come back,**
   [promote it](cluster.md#promoting-the-secondary). Until you do, the configuration
   can't be changed.

**Never** run `portitor request cluster active` on both firewalls. Never run it on one
firewall while the other might still be running and connected to the traffic networks.

## Quick reference

```
sudo portitor show cluster                         # state of this firewall and the other
sudo portitor request cluster switchover           # on the active firewall: hand over to the standby
sudo portitor request cluster active --minutes N   # make this firewall active without the other or the witness
sudo -u portitor portitor-config promote           # on the secondary: take over the configuration
```
