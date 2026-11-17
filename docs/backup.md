<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Backup and recovery

A backup holds a firewall's whole configuration. With a backup you can rebuild a
failed firewall from the ISO in minutes. Make one now, and again after every big
change.

## Making a backup

*Admin → Backup & restore*, *Backup*:

1. Choose a passphrase of at least 10 characters.
2. Download the file and keep it somewhere safe, off the firewall.

The backup holds every secret of the configuration: VPN keys, certificate keys,
passwords. That is why it is encrypted. Keep the passphrase as safe as the file:
**the passphrase can't be recovered**, and a backup without it is useless.

The backup has the configuration, the users and roles, and the directory settings.
It doesn't have the deployment history or the connection to the firewall's own
programs, which belong to the machine.

## Restoring a backup

*Admin → Backup & restore*, *Restore*: choose the file and enter its passphrase.

The restore replaces the configuration in the GUI, but **doesn't change the running
firewall yet**. Review the changes on *Deploy*, then commit and confirm as usual.

A backup from a newer Portitor release than the one installed is refused: update the
firewall first. A restore is also refused while a commit waits for confirmation.

## Rebuilding a failed firewall

When a firewall's hardware or disk fails:

1. Install the replacement from the ISO (see [Installing a firewall](install.md)),
   with the same machine type as before.
2. Give the network interfaces the same names they had. On identical hardware they
   get them by themselves. If the names differ, rename the interfaces in the
   configuration after the restore, before you commit.
3. Log in to the new firewall's GUI from the LAN, and restore the backup (above).
4. Review on *Deploy*, then commit and confirm.

The restore keeps the new machine's own settings that aren't configuration, so the
restored configuration runs on the new hardware.

If the firewall was managed by a portitor-manager, the replacement has a new
certificate. In portitor-manager, open the firewall under *Firewalls* and enter its
new *Certificate fingerprint* (`sudo -u portitor portitor-config fingerprint` on the
firewall prints it), or remove the firewall there and add it again.

## A failed firewall in a cluster

You don't need the backup for a cluster: the other firewall has the whole
configuration.

- **The secondary failed:** under *Admin → Firewalls* on the primary, delete the old
  secondary and commit. Install the replacement from the ISO as *secondary*, and
  join it to the primary as when the cluster was set up (see
  [Firewall clusters](cluster.md#setting-up-a-cluster)).
- **The primary failed:** promote the secondary first (see
  [the cluster runbook](cluster-runbook.md#a-firewall-fails)). Then delete the old
  primary under *Admin → Firewalls*, and add the replacement as the new secondary.

Make backups of a cluster all the same, on its primary. They protect you against
mistakes too, not only against hardware failures.

## Forgotten password

At boot, choose **Portitor password recovery** in the boot menu. The firewall starts
without any network service and offers to:

1. set the password of the console user `portitor`, or
2. reset a GUI user's password, or create a new GUI admin.

Then it reboots. Anyone at the console can do this, so keep the console physically
safe.

A user who has lost their two-factor device and recovery codes: an admin opens the
user under *Admin → Directory* and chooses *Reset 2FA*.
