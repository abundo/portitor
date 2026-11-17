<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Updates

*Admin → Updates* keeps the firewall up to date. Nothing happens until you click a
button.

- **Check for updates** looks for operating system updates and new Portitor
  releases. Security updates are marked.
- **Upgrade N packages** installs the operating system updates. It never removes
  packages, and keeps configuration files you have changed.
- **Install**, next to a Portitor release, updates Portitor. The GUI is away for a
  moment; reload the page when the update is done. Traffic keeps flowing while the
  firewall updates. *Go back* installs an older release the same way.
- **Reboot firewall.** After a kernel update, a banner says that a reboot is
  needed. Traffic stops until the firewall is back up.

Read the release notes before you install a release: the *Dashboard* shows them.

## Before you update

- Make a [backup](backup.md).
- Commit or revert pending changes, and confirm any commit that waits.
- Plan a reboot for a quiet time.

## If an update fails

Before Portitor changes anything, it checks that the new release can read the
firewall's configuration. If it can't (for example, *Go back* to a release older
than the one that last converted the configuration), the update is refused and
nothing changes.

Each update keeps a copy of the release that was installed, with its
configuration as it was before the update. After the update, Portitor checks that
the firewall's services start and answer. If a step or a check fails, it puts the
previous release and its configuration back, starts them again, and stops: the
message says which release runs now. With portitor-manager, the firewalls updated
before the failing one stay on the new release, and those after it are not
touched.

Operating system packages that the update installed stay installed. They don't
affect the previous release.

## Updating a firewall cluster

Update the **secondary first**, then the primary. Each firewall hands its traffic
over to the other before it restarts, so the cluster keeps forwarding; clients lose a
packet or two.

A reboot works the same way. See
[Rebooting a firewall for maintenance](cluster-runbook.md#rebooting-a-firewall-for-maintenance).

## Updating firewalls with portitor-manager

On the manager's machine, run `./install.py` from the new release. It updates the
firewalls the manager manages first, one at a time and the cluster secondaries
first, and then the manager itself.

## Old releases

A firewall older than 1.0.0 can't be updated directly to a later release. Update it
to 1.0.0 first, let it start once, and then update it to the release you want.
Portitor refuses an update that would skip that step, before it changes anything.
