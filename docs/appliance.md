<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Installer ISO and updates

The Portitor ISO installs a complete firewall on an amd64 machine: Debian 13, the
programs the agent needs (nftables, BIND, Kea, radvd, WireGuard), portitor-agent and
portitor-config, which keeps the firewall's configuration and serves its GUI. A single
box is enough.

The agent API listens on 127.0.0.1 only, and the ruleset lets the LAN interface reach
the GUI; the WAN does not. At boot the agent loads the ruleset before it brings up the
interfaces and turns on forwarding, but there is no ruleset before the agent starts:
anything else that configures an interface earlier (a leftover netplan or DHCP client
entry) opens a gap. To serve the GUIs of several firewalls from one place, run
portitor-web, the portal, on another host; see
[Firewall and portal on separate hosts](#firewall-and-portal-on-separate-hosts).

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

Next it asks what the machine runs (see [Firewall and portal on separate hosts](#firewall-and-portal-on-separate-hosts)). The network
page lists the network interfaces with their MAC addresses and whether a cable is
plugged in (*Reload interfaces* updates the list, so you can plug cables in and
watch). It asks for:

- **LAN interface**: where you reach the GUI from.
- **WAN interface**: where the firewall reaches the Internet, for updates and IP lists.
- **LAN IPv4**: *Static* (the default), with the LAN address and its prefix
  length, e.g. `192.168.1.1/24`, or *DHCP*. A DHCP LAN takes no default route from its
  lease; the default route belongs to the WAN.
- **LAN DHCP server** (static LAN only): *Off* (the default) or *On*, with the
  **DHCP range** it hands out, e.g. `192.168.1.100-192.168.1.199`. Clients get the
  LAN address as gateway and the DNS servers below (their IPv4 ones).
- **WAN IPv4**: *DHCP* (the default), which also brings the default gateway, or
  *Static*, with the WAN address and its prefix length and the **default gateway**.
- **DNS servers** the firewall itself uses, for updates and IP lists. The default is
  `1.1.1.1 8.8.8.8`. They are written to `/etc/resolv.conf`; the agent does not change
  that file, not even from the WAN's DHCP lease.
- **Password**: for the user `portitor`, both in the GUI and as the console login,
  which has sudo.
- **Time zone**: used by scheduled tasks.

Before it applies anything it shows the answers: *Apply* applies them, *Change* goes
back to them, and *Swap LAN and WAN* swaps the LAN and WAN interfaces (the addresses stay with the LAN and the WAN), for
when you picked them the wrong way round.

Then it creates the database, starts the agent and the GUI, and deploys a first
configuration:

- the LAN interface with its address, or DHCP, labelled *LAN*,
- the WAN interface, with DHCP or its static address, labelled *WAN*,
- the default route (for a static WAN),
- with the LAN DHCP server on, DHCP on the LAN's prefix (in IPAM) with that range,
- a service, *portitor-mgmt* (TCP 22 and 443), and two input rules, *management
  from the LAN* (the service *portitor-mgmt*) and *ping from the LAN*,
- a forward rule, *LAN to WAN*, that accepts everything from the LAN to the WAN,
- a NAT rule, *masquerade to the WAN*: any source, destination and protocol out of
  the WAN gets the WAN's address,
- every other interface as it is (down, no address).

Output keeps the virtual firewall's *allow all output* rule: the chain's policy drops, and
the rule lets everything the firewall itself sends out.

The screen then shows the GUI's address and its certificate fingerprint. The login
screen shows them too; with a DHCP LAN it shows the LAN's current address. Open
`https://<LAN address>/` from the LAN and log in as `portitor`.
The browser warns about the self-signed certificate; compare the fingerprint it shows
with the one on the screen.

Next steps in the GUI: DHCP (if not turned on here) and DNS for the LAN, and narrower rules than *LAN to WAN* if
you want them. See [portitor-web](portitor-web.md).

If a step fails, the setup shows the error with *Retry* and *Give up*; its log is
`/var/log/portitor-setup.log`. If you give up, it runs again at the next boot, or
run `sudo portitor-setup` after logging in as `portitor` at the console.

## Changing the network later

`sudo portitor-setup`, run again after the first setup, changes the network: the LAN
and WAN interfaces (or swaps them), DHCP or a static address on each, the LAN's DHCP
server, the default gateway, the DNS servers, the time zone and the keyboard layout. The last answers are the defaults. A new password
for `portitor` (GUI and console) is optional; leave it empty to keep the current one. This
is also the way back in when a change in the GUI has locked you out of it.

It then deploys at once, without the confirm timeout:

- the LAN and the WAN get exactly the new settings: their other IPv4 addresses are
  removed, and an address in use on another interface moves;
- the IPv4 default route is the new gateway, or none with a DHCP WAN (whose lease
  brings it);
- the service *portitor-mgmt* gets the GUI port again; the rules *management from
  the LAN* and *ping from the LAN* are enabled and match the new LAN interface; the rule *LAN to WAN* and the NAT rule
  *masquerade to the WAN*, if they are still there, match the new LAN and WAN;
- the LAN and WAN are labelled *LAN* and *WAN*, unless you gave them another
  label;
- with the LAN DHCP server on, the LAN's prefix serves the range; *Off* leaves DHCP
  as it is (turn it off in the GUI);
- a new GUI certificate is made when the LAN address changes, so the browser warns
  again; the new fingerprint is shown (a portitor-web that serves this firewall needs
  it too: the new portal string, below).

Everything else stays: the database, the agent, other interfaces (an interface that
was the LAN or WAN before stays enabled), rules, NAT and DHCP. Run it at the console:
an SSH session over the old LAN address drops.

Do not edit the rule *management from the LAN*, the service *portitor-mgmt* or the LAN interface in a way that
locks you out. If that happens, the auto-rollback restores the previous configuration
as long as you do not confirm the change.

## Firewall and portal on separate hosts

A firewall always keeps its own configuration and serves its GUI. portitor-web, the
portal, can serve the GUIs of several firewalls from another host: each at
`/fw/<name>/`, with the firewall's own login and users. The setup first asks what the
machine runs:

- **both**: the firewall with its GUI, as above.
- **agent**: the same firewall, its GUI served by portitor-web on another host too.
- **web**: portitor-web only, the portal.

**The firewall (agent).** The setup asks the same questions as for *both*, except that
the LAN address must be static (portitor-web reaches the firewall there), and it asks
for **portitor-web's address**: an address or a network, by default the LAN network.
The firewall then believes the browser's address that portitor-web passes on
(`trusted_proxies` in `/etc/portitor/config.yaml`), for its login limits. The GUI is
open from the LAN as for *both*.

The setup ends with a **portal string**, one line that starts with `portitor-portal:`:
the firewall's name, its GUI's URL and its certificate's fingerprint. It names no
secret. Log in over SSH (`ssh portitor@<LAN address>`) and run `sudo portitor-setup
--show-join`, which prints it as plain text, to copy it.

**The portal (web).** The setup asks for the host's interface, DHCP or a static
address with its default gateway, the DNS servers, the password for the console user
`portitor`, and the time zone. The interface is configured in `/etc/network/interfaces`
and portitor-agent and portitor-config are disabled: this host has no firewall and no
users of its own. At the end, paste a firewall's portal string and choose *Add*, or
choose *Later*: log in over SSH and run `sudo portitor-setup --join` (it asks), or
`sudo portitor-setup --join <portal string>`. Each adds the firewall to
`/etc/portitor/web.yaml`; one of the same name is replaced. A portitor-web installed
with `install.py` takes the same entry by hand under `firewalls:` (see
[portitor-web](portitor-web.md#portitor-web)).

Run again, `sudo portitor-setup` changes on the firewall what it changes for *both*,
and portitor-web's address; on the portal, the host's interface and address, the DNS
servers, the time zone, the keyboard layout and the password.

## Updates

*Admin → Updates* updates the firewall. Nothing happens until you click a button.

- **Check for updates** refreshes Debian's package lists (`apt-get update`) and lists
  the Portitor releases on GitHub.
- **Upgrade N packages** upgrades Debian: `apt-get upgrade --with-new-pkgs`. It never
  removes packages, and it keeps configuration files you have changed. Security updates
  are marked.
- **Install** next to a Portitor release runs `install.py --install <release>` on the
  firewall. It updates the agent first, then portitor-config (and migrates its
  database), and restarts both. The GUI is away for a moment; reload the page when the update is
  done. *Go back* installs an older release the same way.
- **Reboot firewall**. After a kernel update, a banner says a reboot is needed.
  Traffic stops until the firewall is back up.

The upgrade and the Portitor update run as transient systemd units
(`portitor-os-upgrade`, `portitor-update`), so they finish even though they restart the
agent. Their output is shown on the page, and is in the journal
(`journalctl -u portitor-update`).

Updating from the GUI needs a copy of `install.py` on the firewall
(`/usr/lib/portitor/install.py`). The ISO installs it, and every `install.py` run since
this feature puts it there. A portitor-web on another host is updated on its own host
with `install.py`, which updates its firewalls first.

An ISO firewall from before portitor-config ran portitor-web with the database. The
update moves that database to portitor-config, which listens on port 8444 on the
firewall, and portitor-web stays on port 443 as the portal to it: the GUI is at the same
address, under `/fw/<host name>/`. Log in again afterwards. `sudo portitor-setup`, run
again, puts portitor-config itself on port 443.

A portitor-web on a host of its own, from before portitor-config, had the database
there. Update it from that host with `install.py`, which needs SSH to the firewall
(as for `--agent`): it finds the firewall in the database, updates it first, copies
the database to its portitor-config and lists it in `web.yaml`, and the firewall
trusts portitor-web's address (`trusted_proxies`). The GUI is then at
`/fw/<firewall's host name>/`. Updating the firewall alone first (from the GUI)
leaves its portitor-config stopped and empty; don't create an admin there, as a
commit from it would replace the firewall's configuration.

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
