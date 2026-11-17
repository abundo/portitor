<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Lost connectivity

What to do when you can't reach the GUI, or traffic stops flowing. Start at the
top: the first sections are the most common causes.

## You lost the GUI right after a commit

**Wait.** Every commit has to be confirmed. If you don't confirm it, the firewall
goes back to the configuration it ran before when the timer runs out (two minutes by
default). Then reload the page.

If you have the console (screen and keyboard, serial, or the hypervisor's console),
log in as `portitor` and roll back at once:

```
sudo portitor rollback
```

## You confirmed a change that locked you out

Once a change is confirmed, it stays. Use the console:

1. Log in as `portitor`.
2. Run `sudo portitor-setup`. It shows your LAN and WAN settings as they are, and
   applies them again: the LAN address, and the rules that let the LAN reach the GUI
   and SSH. The rest of the configuration stays as it is.
3. Log in to the GUI from the LAN, and fix what went wrong.

## You forgot the password

Use **Portitor password recovery** in the boot menu. See
[Backup and recovery](backup.md#forgotten-password).

## The GUI says "agent unreachable"

The GUI works, but can't reach the part of the firewall that runs the configuration.
Traffic usually still flows. On the console:

```
sudo systemctl status portitor-agent
sudo journalctl -u portitor-agent -n 50
```

`sudo systemctl restart portitor-agent` restarts it. A commit waiting for confirmation
is rolled back, and in a firewall cluster the active firewall hands over to the
standby first.

## The LAN can't reach the Internet

Check these in order:

1. **Does the firewall have its WAN address?** *Services → DHCP*, *DHCP info*, shows
   the firewall's own DHCP leases. *Network → Interfaces* shows the WAN's addresses.
2. **Can the firewall itself reach the Internet?** *Tools → Connectivity*: ping
   `1.1.1.1`. If that fails, the problem is at the WAN or your provider.
3. **Does DNS work?** *Tools → Connectivity*, a DNS query to the firewall's LAN
   address. If addresses work but names don't, check *Services → DNS*.
4. **Is there a route?** *Routing → Tables* should show a default route out of the
   WAN.
5. **Do the rules let it through?** *Firewall → Rules*, the *Forward* tab: each
   rule's counter shows whether it matches. Turn on *Log* for a rule, or for the
   last row (what no rule accepted), and watch *Logged packets* in the log panel.
6. **Is NAT there?** The *Postrouting* tab needs a masquerade rule out of the WAN.

*Tools → Packet capture* on the LAN and the WAN shows where the packets stop.

## One device can't reach another

- Different networks: a forward rule must allow it, in that direction.
- Same network: the firewall isn't in the path. Check the devices and the switch.
- *Network → Neighbours* shows which devices the firewall sees on each interface.

## A firewall cluster

When neither firewall forwards, or both show *fenced*, see
[the cluster runbook](cluster-runbook.md).

## Useful console commands

As `portitor`, on the firewall's console or over SSH:

```
ip -br addr                              # interfaces, addresses, link state
sudo portitor show ip neighbours         # devices seen on each interface
sudo portitor show cluster               # a cluster firewall's state
sudo portitor confirm                    # confirm a pending commit
sudo portitor rollback                   # roll back a pending commit
sudo portitor request dhcp renew <wan>   # renew the WAN's DHCP lease
```
