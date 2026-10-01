<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Installer ISO and updates

The Portitor ISO installs a complete firewall on an amd64 machine: Debian 13, the
programs the agent needs (nftables, BIND, Kea, radvd, WireGuard),
portitor-agent and portitor-web. The GUI runs on the firewall itself, so a single box
is enough.

This is less strict than the split setup in the [README](../README.md#install), where
the GUI runs on another host. Here the agent API listens on 127.0.0.1 only, and the
ruleset lets the LAN interface reach the GUI; the WAN does not. At boot the agent loads
the ruleset before it brings up the interfaces and turns on forwarding, but there is no
ruleset before the agent starts: anything else that configures an interface earlier
(a leftover netplan or DHCP client entry) opens a gap. To move the GUI to
another host later, install portitor-web there with `install.py`, point it at the
agent, and change the agent's `listen` and `allow_from` in
`/etc/portitor/agent.yaml`. To split them from the start, see
[Firewall and GUI on separate hosts](#firewall-and-gui-on-separate-hosts).

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

The setup is a text UI of a few pages, with *Back* and *Next* (Tab moves between
fields, Enter goes on, Escape goes back). It first asks for the **keyboard layout**:
pick one from the list, or type to search the layout names and codes (e.g. `se`). It
applies at once, so the password is typed with it.

Next it asks what the machine runs (see [Firewall and GUI on separate hosts](#firewall-and-gui-on-separate-hosts)). The network
page lists the network interfaces with their MAC addresses and whether a cable is
plugged in (*Reload interfaces* updates the list, so you can plug cables in and
watch). It asks for:

- **LAN interface**: where you reach the GUI from.
- **WAN interface**: where the firewall reaches the Internet, for updates and IP lists.
- **LAN IPv4**: *Static* (the default), with the LAN address and its prefix
  length, e.g. `192.168.1.1/24`, or *DHCP*. A DHCP LAN takes no default route from its
  lease; the default route belongs to the WAN.
- **WAN IPv4**: *DHCP* (the default), which also brings the default gateway, or
  *Static*, with the WAN address and its prefix length and the **default gateway**.
- **DNS servers** the firewall itself uses, for updates and IP lists. The default is
  `1.1.1.1 8.8.8.8`. They are written to `/etc/resolv.conf`; the agent does not change
  that file, not even from the WAN's DHCP lease.
- **Password**: for the GUI user `admin` and for the console login `portitor`, who has
  sudo.
- **Time zone**: used by scheduled tasks.

Before it applies anything it shows the answers: *Apply* applies them, *Change* goes
back to them, and *Swap LAN and WAN* swaps the LAN and WAN interfaces (the addresses stay with the LAN and the WAN), for
when you picked them the wrong way round.

Then it creates the database, starts the agent and the GUI, and deploys a first
configuration:

- the LAN interface with its address, or DHCP, labelled *LAN*,
- the WAN interface, with DHCP or its static address, labelled *WAN*,
- the default route (for a static WAN),
- three input rules, *portitor-web from the LAN* (TCP 443), *SSH from the LAN* and
  *ping from the LAN*,
- a forward rule, *LAN to WAN*, that accepts everything from the LAN to the WAN,
- a NAT rule, *masquerade to the WAN*: any source, destination and protocol out of
  the WAN gets the WAN's address,
- every other interface as it is (down, no address).

Output keeps the instance's *allow all output* rule: the chain's policy drops, and
the rule lets everything the firewall itself sends out.

The screen then shows the GUI's address and its certificate fingerprint. The login
screen shows them too; with a DHCP LAN it shows the LAN's current address. Open
`https://<LAN address>/` from the LAN and log in as `admin`.
The browser warns about the self-signed certificate; compare the fingerprint it shows
with the one on the screen.

Next steps in the GUI: DHCP and DNS for the LAN, and narrower rules than *LAN to WAN* if
you want them. See [portitor-web](portitor-web.md).

If a step fails, the setup shows the error with *Retry* and *Give up*; its log is
`/var/log/portitor-setup.log`. If you give up, it runs again at the next boot, or
run `sudo portitor-setup` after logging in as `portitor` at the console.

## Changing the network later

`sudo portitor-setup`, run again after the first setup, changes the network: the LAN
and WAN interfaces (or swaps them), DHCP or a static address on each, the default gateway,
the DNS servers, the time zone and the keyboard layout. The last answers are the defaults. A new password
for `admin` and `portitor` is optional; leave it empty to keep the current one. This
is also the way back in when a change in the GUI has locked you out of it.

It then deploys at once, without the confirm timeout:

- the LAN and the WAN get exactly the new settings: their other IPv4 addresses are
  removed, and an address in use on another interface moves;
- the IPv4 default route is the new gateway, or none with a DHCP WAN (whose lease
  brings it);
- the rules *portitor-web from the LAN*, *SSH from the LAN* and *ping from the LAN*
  are enabled and match the new LAN interface; the rule *LAN to WAN* and the NAT rule
  *masquerade to the WAN*, if they are still there, match the new LAN and WAN;
- the LAN and WAN are labelled *LAN* and *WAN*, unless you gave them another
  label;
- a new GUI certificate is made when the LAN address changes, so the browser warns
  again; the new fingerprint is shown.

Everything else stays: the database, the agent, other interfaces (an interface that
was the LAN or WAN before stays enabled), rules, NAT and DHCP. Run it at the console:
an SSH session over the old LAN address drops.

Do not edit the rules *portitor-web from the LAN* or the LAN interface in a way that
locks you out. If that happens, the auto-rollback restores the previous configuration
as long as you do not confirm the change.

## Firewall and GUI on separate hosts

The setup first asks what the machine runs:

- **both**: the firewall with its GUI, as above.
- **agent**: a firewall managed by portitor-web on another host.
- **web**: portitor-web only, managing a firewall on another host.

Install the firewall first.

**The firewall (agent).** The setup asks the same questions as above, except that the
LAN address must be static (portitor-web has to find the firewall there), and it asks
for **portitor-web's address**: an address or a network, by default the LAN network.
The agent listens on port 8443 and only takes calls from that address; the
anti-lockout rule keeps port 8443 and SSH open from it whatever the rules say. The
password is for the console login `portitor` only.

Nothing is deployed yet: until portitor-web deploys a first configuration, the setup
puts the LAN address on the LAN interface (`portitor-setup-lan.service`, at every boot
until then). There is no other address and no route, so portitor-web must be on the
LAN network for the first deploy.

The setup ends with a **join string**, one line that starts with `portitor-join:`. It
holds the agent's URL, its token and certificate fingerprint, and the LAN and WAN
answers. The token is a password to the firewall: keep the string to yourself. It is
too long to type comfortably, so log in over SSH (`ssh portitor@<LAN address>`) and run
`sudo portitor-setup --show-join`, which prints it as plain text, to copy it.

**The GUI host (web).** The setup asks for the host's interface, DHCP or a static
address with its default gateway, the DNS servers, the password for `admin` and
`portitor`, and the time zone. The interface is configured in `/etc/network/interfaces`
and portitor-agent is disabled, so this host has no Portitor firewall of its own. At
the end, paste the join string and choose *Deploy*, or choose *Later* and paste it later: log in over SSH
and run `sudo portitor-setup --join`.

The join deploys the firewall's first configuration, as for *both*: its LAN and WAN,
the default route, *SSH from the LAN*, *ping from the LAN*, *LAN to WAN* and the
masquerade. There is no *portitor-web from the LAN* rule, since the GUI is not on the
firewall.

A portitor-web installed with `install.py` takes the join string too:

```sh
sudo runuser -u portitor -- portitor-web -f /etc/portitor/web.yaml bootstrap --join -
```

Paste the string, then press Enter and Ctrl-D. Both refuse once portitor-web has
deployed something. You can also enter the agent URL, token and fingerprint by hand in
*Settings → Agent*, but then configure the firewall's LAN interface with its address
before the first deploy. Otherwise the deploy takes the LAN address away.

Run again, `sudo portitor-setup` changes less on a split setup. On the firewall it
changes portitor-web's address, the DNS servers, the time zone, the keyboard layout and
the console password; the network is portitor-web's to change. On the GUI host it
changes the host's interface and address, the DNS servers, the time zone, the keyboard
layout and the password.

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
