<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Implementation notes moved out of the user guides

At 1.1.0 the user guides in `docs/` lost their implementation details. What was taken
out of a feature guide and isn't already in an `arch-*.md` file is kept here. Whole
guides that were replaced are `arch-cluster-guide.md`, `arch-gui-guide.md`,
`arch-appliance-guide.md` and `arch-deployments-guide.md`.

## docs/openvpn.md

- On the default virtual firewall (the host itself) OpenVPN runs as the
  distribution's `openvpn-server@portitor-udp.service` and
  `openvpn-server@portitor-tcp.service`, from `/etc/openvpn/server/`.
- On another virtual firewall it runs in the virtual firewall
  (`portitor-openvpn-udp@<name>.service`, `portitor-openvpn-tcp@<name>.service`).
- The password is checked by portitor-agent, which OpenVPN asks for each login
  through its management socket; no script runs. The agent reaches the directory
  servers from the firewall host.

## docs/bgp.md

## How it runs

The default virtual firewall (the host) runs the distribution's `frr.service` from
`/etc/frr` (`frr.conf`, `daemons`, `vtysh.conf`; files that were there before are
kept as `*.portitor-orig`). Every other virtual firewall runs
`portitor-frr@<name>.service`, with its files in
`/etc/portitor/instances/<name>/frr`, mounted as FRR's *pathspace*
`/etc/frr/<name>`. Its daemons keep the capability CAP_SYS_ADMIN, which FRR needs to
start, where the other daemons of a virtual firewall drop it.

A changed configuration is applied with FRR's `frr-reload.py`, which keeps the
sessions up; a change to the daemons FRR runs, or a reload that fails, restarts it.

*Static* in *Redistribute* means the static routes Portitor installs (in the kernel
routing table, so FRR sees them as kernel routes): FRR's `redistribute kernel`.

On the firewall, as root, `vtysh` (`vtysh -N <name>` for a virtual firewall) shows
everything FRR has: `show bgp summary`, `show bgp neighbors`, `show bgp ipv4
unicast`. *BGP info* leaves out the BGP table of an address family with more than
2000 routes (a full Internet table); vtysh shows it.

## docs/snmp.md

- On the **default virtual firewall** (the host itself) snmpd runs as the
  distribution's `snmpd.service`. Its config replaces `/etc/snmp/snmpd.conf` (the
  original is kept as `snmpd.conf.portitor-orig`).
- On **another virtual firewall** snmpd runs in the virtual firewall
  (`portitor-snmpd@<name>.service`), so it shows that virtual firewall's
  interfaces, addresses and routes. The system-wide values (load, memory, disks)
  are the host's.
