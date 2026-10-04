<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# NTP

Under **Services → NTP**, each virtual firewall can run [chrony](https://chrony-project.org/),
an NTP client that keeps the time from the servers you list, and an NTP server for
the clients behind it.

- On the **default virtual firewall** (the host itself) chrony sets the firewall's
  clock. Its config replaces `/etc/chrony/chrony.conf` (the original is kept as
  `chrony.conf.portitor-orig`). With NTP turned off there, Portitor leaves the
  distribution's chrony alone; turned off after having been on, chrony is stopped,
  and the clock is no longer kept.
- On **another virtual firewall** chrony keeps the time in the virtual firewall's
  own network, through its own interfaces, but never sets the clock, which is
  the host's. It is there to serve the time to the virtual firewall's clients.

The page has two tabs: **Info** shows the time sources as chrony has them (state,
stratum, reach, offset, NTS), how it keeps time (tracking) and what it has served,
refreshed every 5 seconds; **Configuration** holds the settings below.

## Servers

Each server is an IP address or a host name, with:

- **Pool**: the name resolves to several servers (`2.debian.pool.ntp.org`), which
  chrony uses as several sources.
- **iburst**: send a burst of requests at start, for a quicker first sync.
- **NTS**: authenticate the server with Network Time Security (RFC 8915). The
  server must support it (`time.cloudflare.com`, `nts.netnod.se`, `ptbtime1.ptb.de`);
  NTS-KE uses TCP port 4460 to the server.

## Serving the time

The firewall answers NTP clients only on the interfaces turned on in the table
(**Answer NTP clients**): the ruleset accepts UDP port 123 there (the auto rule
"ntp server"), as it does DNS. With none, it serves no one.

**Allowed clients** narrows that further to prefixes, or hosts and prefixes by name.
Empty, any client on those interfaces gets the time.
