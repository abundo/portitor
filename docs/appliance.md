<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Installer ISO and updates

The Portitor ISO installs a complete firewall on an amd64 machine: Debian 13, the
programs the agent needs (nftables, BIND, Kea, radvd, WireGuard), PostgreSQL,
portitor-agent and portitor-web. The GUI runs on the firewall itself, so a single box
is enough.

This is less strict than the split setup in the [README](../README.md#install), where
the GUI runs on another host. Here the agent API listens on 127.0.0.1 only, and the
ruleset lets the LAN interface reach the GUI; the WAN never does. To move the GUI to
another host later, install portitor-web there with `install.py`, point it at the
agent, and change the agent's `listen` and `allow_from` in
`/etc/portitor/agent.yaml`.

AppArmor stays on. Debian's profiles for BIND and Kea get Portitor's paths added in
`/etc/apparmor.d/local/` (by `install.py`, as on any Debian host).

## Installing

1. Download `portitor-<version>-amd64.iso` from a GitHub release (check it against
   the `.sha256` next to it), or build it (below). Write it to a USB stick
   (`dd if=portitor-….iso of=/dev/sdX bs=4M`) and boot the machine from it. BIOS and
   UEFI both work.
2. The Debian installer runs by itself. It asks which disk to install on and asks
   before erasing it. It asks for network settings only when there is no DHCP. It
   downloads the packages, so one interface needs Internet access during the
   installation.
3. The machine reboots into the first-boot setup on the screen.

## First-boot setup

The setup lists the network interfaces with their MAC addresses and whether a cable is
plugged in (*r* reloads the list, so you can plug cables in and watch). It then asks
for:

- **LAN interface**: where you reach the GUI from.
- **LAN address** with its prefix length, e.g. `192.168.1.1/24`.
- **Default gateway** (optional): only when the firewall reaches the Internet through
  the LAN for now. Leave it empty if you will configure a WAN interface with DHCP in the
  GUI.
- **DNS servers** the firewall itself uses, for updates and IP lists. The default is
  the gateway, or public resolvers without one. They are written to
  `/etc/resolv.conf`; the agent does not change that file, not even from the WAN's
  DHCP lease.
- **Password**: for the GUI user `admin` and for the console login `portitor`, who has
  sudo.
- **Time zone**: used by scheduled tasks.

Then it creates the database, starts the agent and the GUI, and deploys a first
configuration:

- the LAN interface with its address,
- the default route (if you gave one),
- two input rules, *portitor-web from the LAN* (TCP 443) and *ping from the LAN*,
- every other interface as it is (down, no address).

The screen then shows the GUI's address and its certificate fingerprint. The login
screen shows them too. Open `https://<LAN address>/` from the LAN and log in as `admin`.
The browser warns about the self-signed certificate; compare the fingerprint it shows
with the one on the screen.

Next steps in the GUI: configure the WAN interface (*Network → Interfaces*, IPv4 mode
DHCP), a masquerade rule (*Firewall → NAT*), forward rules from the LAN to the WAN, and
DHCP and DNS for the LAN. See [portitor-web](portitor-web.md).

If a step fails, the setup shows the error and offers to retry it; its log is
`/var/log/portitor-firstboot.log`. If you give up, it runs again at the next boot, or
run `sudo /usr/lib/portitor/firstboot.py --force` after logging in as `portitor` at the
console.

Do not edit the rules *portitor-web from the LAN* or the LAN interface in a way that
locks you out. If that happens, the auto-rollback restores the previous configuration
as long as you do not confirm the change.

## Updates

*Admin → Updates* updates the firewall. Nothing happens until you click a button.

- **Check for updates** refreshes Debian's package lists (`apt-get update`) and lists
  the Portitor releases on GitHub.
- **Upgrade N packages** upgrades Debian: `apt-get upgrade --with-new-pkgs`. It never
  removes packages, and it keeps configuration files you have changed. Security updates
  are marked.
- **Install** next to a Portitor release runs `install.py --install <release>` on the
  firewall. It updates the agent first, then portitor-web (and migrates its database),
  and restarts both. The GUI is away for a moment; reload the page when the update is
  done. *Go back* installs an older release the same way.
- **Reboot firewall**. After a kernel update, a banner says a reboot is needed.
  Traffic stops until the firewall is back up.

The upgrade and the Portitor update run as transient systemd units
(`portitor-os-upgrade`, `portitor-update`), so they finish even though they restart the
agent. Their output is shown on the page, and is in the journal
(`journalctl -u portitor-update`).

Updating from the GUI needs a copy of `install.py` on the firewall
(`/usr/lib/portitor/install.py`). The ISO installs it, and every `install.py` run since
this feature puts it there. When portitor-web runs on another host, *Install* updates
only the agent. Update portitor-web on its own host with `install.py`, after the agent.

## Building the ISO

`iso/build.sh` remasters Debian's netinst ISO. It needs `xorriso` and `curl`, and Go
and npm to build Portitor from the source tree:

```sh
iso/build.sh                     # this tree -> build/portitor-<version>-amd64.iso
iso/build.sh --release v1.2.0    # a GitHub release instead
```

It downloads the current Debian 13 netinst ISO (checked against Debian's SHA256SUMS)
and caches it in `~/.cache/portitor-iso`. It adds `preseed.cfg`, the Portitor release
archive and the first-boot setup to the ISO, and replaces the boot menus.

`iso/vm.sh` runs the ISO in QEMU with a WAN and a LAN interface, and forwards the GUI
to `https://127.0.0.1:28443/`:

```sh
iso/vm.sh install build/portitor-<version>-amd64.iso
iso/vm.sh run
```

`iso/build.sh --test` builds an ISO that installs without any question, onto
`/dev/vda`, and answers the first-boot setup from `iso/test.answers`: LAN is the VM's
second interface, `192.168.1.1/24`, password `portitor-test`. It erases the first
virtio disk without asking, so it is only for the virtual machine.
