<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Installing a firewall

A Portitor firewall is installed from the **Portitor ISO**. It installs a complete
firewall on an amd64 machine or virtual machine, and needs no network while it
installs: everything is on the ISO.

## What to install

Decide first what the machine will be. The first-boot setup asks for it as the
*machine type*:

| Machine type | What it is | Use it for |
|---|---|---|
| **firewall** | A standalone firewall with its own GUI. | Most installations: a home, an office, a site. |
| **managed** | The same firewall, also managed by a portitor-manager. | Several firewalls managed from one place. |
| **manager** | portitor-manager only: no firewall on this machine. | The one place where you manage several firewalls and clusters. See [portitor-manager](portitor-manager.md). |
| **primary** / **secondary** | The two firewalls of a firewall cluster. | A firewall that keeps forwarding when one machine fails. See [Firewall clusters](cluster.md). |

Every firewall keeps its own configuration and has its own GUI, managed or not.
You can add a portitor-manager later without reinstalling the firewall.

## What you need

- A machine with at least two network interfaces: one for the **WAN** (the Internet)
  and one for the **LAN**. A firewall cluster needs two more on each firewall (see
  [Firewall clusters](cluster.md#what-you-need)).
- A USB stick, or a virtual machine that can boot the ISO. BIOS and UEFI both work.
- A screen and keyboard for the first boot. A serial console works too after the
  installation.

## Installing

1. Download `portitor-<version>-amd64.iso` from the release page, and check it against
   the `.sha256` file next to it.
2. Write it to a USB stick (`dd if=portitor-<version>-amd64.iso of=/dev/sdX bs=4M`)
   and boot the machine from it.
3. The installer runs by itself. It asks which disk to install on, and asks again
   before it erases it.
4. The machine reboots into the **first-boot setup**.

## The first-boot setup

The setup is a text screen with its steps listed on the left. *Back* and *Next* (or
F7 and F8) move between steps, Tab moves between fields, and F10 jumps to the last
step, where the setup applies your answers.

1. **Keyboard layout.** Type to search, for example `se`.
2. **Machine type.** See [What to install](#what-to-install).
3. **Interfaces.** The network interfaces are listed with their MAC addresses and
   whether a cable is plugged in. *Reload interfaces* updates the list, so you can plug
   in cables one at a time and watch which interface is which. Pick an interface and
   press the number of its role: **WAN** or **LAN**.
4. **Addresses.**
   - **LAN:** a static address such as `192.168.1.1/24` (the default), or DHCP.
   - **LAN DHCP server:** on or off. When it is on, give the range it hands out, for
     example `192.168.1.100-192.168.1.199`.
   - **WAN:** DHCP from your provider (the default), or a static address with its
     default gateway.
   - **DNS servers** the firewall itself uses. Leave this empty to use the ones your
     provider hands out over DHCP.
   - **Password** for the user `portitor`. It is both the GUI login and the console
     login.
   - **Time zone.**

The setup shows a summary before it applies anything. *Swap LAN and WAN* fixes it if
you picked the interfaces the wrong way round.

If a step fails, the setup shows the error with *Retry* and *Give up*. If you give
up, the setup runs again at the next boot. You can also log in on the console as
`portitor` and run `sudo portitor-setup`.

## What you get

The firewall starts with a basic, safe configuration:

- The LAN can reach the GUI and SSH on the firewall, and can ping it.
- The LAN can reach the Internet, with NAT to the WAN address.
- Nothing from the WAN reaches the firewall or the LAN.
- The firewall itself can reach out, for updates and downloads.
- The LAN DHCP server, if you turned it on.

The screen then shows the GUI's address and its certificate fingerprint. Open
`https://<LAN address>/` from a computer on the LAN and log in as `portitor`. The
browser warns about the self-signed certificate. Compare the fingerprint it shows
with the one on the screen before you continue.

Next: [A basic LAN/WAN firewall](first-firewall.md).

## Changing the network later

Run `sudo portitor-setup` again on the console to change the LAN and WAN
interfaces, their addresses, the LAN DHCP server, the gateway, the DNS servers, the
time zone, the keyboard layout or the password. Your answers from last time are
filled in. Everything else in the configuration stays as it is.

Use the console rather than SSH: an SSH session over the old LAN address drops.

This is also the way back in when a change in the GUI has locked you out. See
[Lost connectivity](troubleshooting.md).

## Serial console

The installed system has a serial console on the first serial port (115200 baud),
with the boot menu and a login prompt. The first-boot setup runs on the screen only.
In Proxmox VE, add a serial port to the VM and open its console as **xterm.js**, which
supports copy and paste.

## Installing without the ISO

On an existing Debian 13 machine, `install.py` from a release installs the same
programs. See the [README](../README.md#install).
