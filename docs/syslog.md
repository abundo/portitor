<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Syslog

A firewall keeps its logs in the systemd journal: the agent's, the firewall's
services' (BIND, Kea, FRR, OpenVPN, ...) and those of every virtual firewall on it.
Under **Services → Syslog** you see the journal and send it to remote syslog
servers (a SIEM, Graylog, a central rsyslog or syslog-ng) with
[rsyslog](https://www.rsyslog.com/).

Syslog is the firewall's, not a virtual firewall's: the page shows the firewall of
the virtual firewall selected in the top bar, and its servers are kept on the
firewall's default virtual firewall. Global admins and viewers see the page; only
global admins change the servers and follow the journal, which holds every virtual
firewall's logs. On an HA pair both hosts send their own journal to the servers.

## Syslog info

- **rsyslog**: its unit (`rsyslog.service`), whether it runs and since when. It runs
  only while there are syslog servers.
- **Syslog servers**: the servers of the deployed configuration.
- **Journal**: its size on disk, and whether it is kept over reboots
  (`/var/log/journal`) or in memory only (`/run/log/journal`); the oldest entry.
- **Journal**: the journal as it comes (`journalctl --follow`), starting with its
  last 500 entries, with a filter over the lines.

## Syslog configuration

Each server has:

- **Address**: an IPv4 or IPv6 address (no host names).
- **Protocol** and **Port**: UDP or TCP, port 514 by default.
- **Format**: RFC 3164 (BSD syslog, rsyslog's traditional forward format) or
  RFC 5424. RFC 5424 over TCP is framed by octet counting (RFC 6587).
- **Severity**: the entries of this severity and the more urgent ones are sent;
  `info` leaves out only debug messages.

A disabled server is left out. Commit to apply a change.

rsyslog reads the journal (imjournal) and sends each server its entries from its own
queue, so a server that is down holds up neither the others nor the firewall. TCP
messages wait in the queue (up to 10,000) and are sent when the server answers
again; UDP messages sent while a server is down are lost. On its first start rsyslog
sends only what is logged from then on, not the journal's older entries.

The firewall's output chain accepts the messages to the servers by itself (the auto
rule "syslog"), whatever its own rules say.

rsyslog's config replaces `/etc/rsyslog.conf` (the original is kept as
`rsyslog.conf.portitor-orig`): it only forwards, and writes no log files of its own
(`/var/log/syslog` and the like); the journal keeps the logs on the firewall.
Messages are sent in clear text: TLS is not offered.
