<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# SNMP

Under **Services → SNMP**, each virtual firewall can run an SNMP agent
([net-snmp](http://www.net-snmp.org/)'s snmpd), so management platforms (LibreNMS,
Zabbix, PRTG, Observium, ...) can monitor it. The agent is read-only and answers
the whole tree it has: the system group, interfaces and their counters (IF-MIB),
addresses, routes and protocol statistics (IP-MIB, IP-FORWARD-MIB, TCP/UDP-MIB),
and the host's load, memory and disks (HOST-RESOURCES-MIB, UCD-SNMP-MIB).

- On the **default virtual firewall** (the host itself) snmpd runs as the
  distribution's `snmpd.service`. Its config replaces `/etc/snmp/snmpd.conf` (the
  original is kept as `snmpd.conf.portitor-orig`).
- On **another virtual firewall** snmpd runs in the virtual firewall
  (`portitor-snmpd@<name>.service`), so it shows that virtual firewall's
  interfaces, addresses and routes. The system-wide values (load, memory, disks)
  are the host's.

## Portitor's own state (PORTITOR-MIB)

The default virtual firewall's agent also answers Portitor's state: what the CLI
shows with `info from state` (the virtual firewalls' interfaces, routes, WireGuard
peers, DHCP leases, neighbours, rule and rate-limit counters, BGP, OSPF, IS-IS,
VRRP, BFD, NTP, NAT64, OpenVPN, and the host, the agent and the HA pair). It is
served by portitor-config, connected to snmpd over AgentX, from a snapshot no more
than about 10 seconds old, for every virtual firewall (the host's agent is the
whole firewall's). A virtual firewall's own agent doesn't answer it.

The MIB is generated from the YANG modules: `portitor-config mib` prints it (it is
also `deploy/mib/PORTITOR-MIB.txt`); load it into the management platform. A list
is a table indexed by its keys and those of the lists around it (a virtual
firewall's interfaces by the virtual firewall's name and the interface's name, as
strings); a list without keys by its row number; a list of values is one string,
the values separated by commas. Numbers keep their meaning across versions: a new
leaf gets a new number.

It is under `1.3.6.1.4.1.8072.9999.9999.1` (net-snmp's arc for experiments) until
Portitor has an enterprise number; `snmp: {base_oid: ...}` in
`/etc/portitor/config.yaml` moves it, and `portitor-config mib` follows.
`snmp: {agentx: "off"}` turns the subagent off.

## Settings

- **Location** and **Contact**: `sysLocation` and `sysContact`. `sysName` is the
  host name.
- **SNMPv2c community**: a read-only community, limited to the allowed clients.
  It is sent in clear text; use SNMPv3 users where the platform supports them.
  Leave it empty for SNMPv3 only. Like a password, it is never shown again once
  saved: leave the field empty to keep it, or turn on **Remove**.

Turning SNMP on needs a community or at least one SNMPv3 user.

## SNMPv3 users

Each user is read-only, with:

- **Authentication**: SHA-256, SHA-512 or SHA (SHA-1), and a password of 8 to 64
  characters. MD5 is not offered.
- **Privacy**: AES (128-bit) with its own password, which encrypts the requests and
  answers (authPriv); or none, for authentication only (authNoPriv). DES is not
  offered.

Passwords can't contain spaces, quotes, `#` or `\`. They are write-only, as the
community is. A disabled user is left out.

The agent keeps its engine id (which SNMPv3 managers know it by) across restarts.

## Answering requests

The firewall answers SNMP only on the interfaces turned on in the table
(**Answer SNMP**): the ruleset accepts UDP port 161 there (the auto rule "snmp"). With
none, it answers no one.

**Allowed clients** narrows that to the management platforms' prefixes, or hosts and
prefixes by name: the auto rule matches them as its source (the read-only address
list `snmp_clients` under Hosts & prefixes), and the community is limited to them
too. Empty, any client on those interfaces may ask.

Traps and notifications are not sent; platforms poll.
