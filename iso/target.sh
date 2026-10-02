#!/bin/sh
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Runs in the installed system (chroot) at the end of the installation:
# installs Portitor from the release archive on the ISO and prepares the
# first-boot setup (portitor-setup.py).
set -eu
d=/tmp/portitor-iso

mkdir -p "$d/release"
tar -xzf "$d/portitor.tar.gz" -C "$d/release"
root=$(dirname "$(find "$d/release" -maxdepth 2 -name install.py | head -n 1)")
# Binaries, units, example configs and /usr/lib/portitor/install.py.
# Nothing is started; portitor-setup configures and starts both.
python3 "$root/install.py" --local "$root" --web --agent --yes

# In PATH, next to the binaries: run again, it changes the LAN and WAN.
install -D -m 0755 "$d/portitor-setup.py" /usr/bin/portitor-setup
install -D -m 0644 "$d/portitor-firstboot.service" /etc/systemd/system/portitor-firstboot.service
systemctl enable portitor-firstboot.service
# SSH is open from the LAN (the portitor-mgmt service).
systemctl enable ssh.service
# Only in an ISO built with --test: answers, so the setup asks nothing.
if [ -f "$d/firstboot.answers" ]; then
	install -m 0600 "$d/firstboot.answers" /etc/portitor/firstboot.answers
fi

# The agent runs BIND, Kea and radvd per instance (portitor-*@ units).
systemctl mask named.service kea-dhcp4-server.service kea-dhcp6-server.service \
	kea-ctrl-agent.service kea-dhcp-ddns-server.service radvd.service

# The agent owns the interfaces: nothing else may configure them (a second
# DHCP client on the WAN keeps the agent from getting a lease).
cat >/etc/network/interfaces <<'IFACES'
# The Portitor agent configures every other interface.
auto lo
iface lo inet loopback
IFACES

# Conntrack timestamps (the Connections page's start times) in every
# namespace: new namespaces take the module's default, not the root's sysctl.
echo 'options nf_conntrack tstamp=1' >/etc/modprobe.d/portitor-conntrack.conf

# Keep the journal (update jobs are read from it) across reboots.
mkdir -p /var/log/journal
