<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# DNS blocklists

A DNS blocklist is a public list of domains known for malware, phishing, scams or
command-and-control servers. With one in place, the DNS server of a virtual firewall
won't resolve those names. A client that looks one up gets "no such name" and never
connects. In BIND this is a *response policy zone* (RPZ). Portitor downloads the list,
keeps it current and loads it into BIND.

A blocklist works only for clients that use the firewall as their DNS server: the
interfaces where *Respond to DNS queries* is on, under *Services → DNS → DNS server*.
To stop clients from going around it, add a forward rule that drops DNS (port 53) and
DNS over TLS (853) to anywhere but the firewall.

## The lists

| Blocklist | What it blocks |
|---|---|
| Hagezi Threat Intelligence Feeds (full) | Malware, phishing, scams, cryptojacking and command and control. Over 4 million entries in two files: BIND needs gigabytes of memory for it. |
| Hagezi TIF (medium) | The most important feeds of the full list, about 900 000 entries. A good default. |
| Hagezi TIF (mini) | The medium list cut to about 400 000 entries, for small firewalls. |
| Hagezi Multi PRO | Ads, trackers and telemetry as well as threats. Now and then a site needs an allowed name. |
| abuse.ch URLhaus | Hosts that serve malware, updated every 5 minutes. Needs a free key (below). |
| OISD big | Ads, trackers, malware and phishing, with few false positives. |
| OISD small | The most common of those, about 120 000 entries. |
| OISD NSFW | Adult sites. |

Check each list's licence before you use it commercially.

## Adding one

1. *Services → DNS*, tab *Blocklists*, button *New blocklist*.
2. Pick the list under *Blocklist*. This fills in the name, description, URLs and
   download interval.
3. *Action*: what a blocked name gets.
   - *NXDOMAIN*: the name does not exist. Use this unless you have a reason not to.
   - *NODATA*: the name exists but has no records.
   - *Drop*: no answer at all, so the client waits until it times out.
   - *Log only*: the answer is the usual one, and the query is logged as it would have
     been blocked. Use it to try a list before it blocks anything.
4. Save and commit. The firewall downloads the list right away. After that it downloads
   it again at the chosen interval, asking only for changes. BIND reloads the list when
   it has changed.

The *State* column shows how the last download went, *Entries* how many names the list
has and *Updated* when it was last checked. Hover over the state to see the error, or
when the next download is due. The download button next to Edit fetches the list now.
A failed download keeps the last good list in force and is tried again within 15
minutes.

A name in a list also blocks the names below it: blocking `bad.example` blocks
`www.bad.example` too.

## URLhaus and its key

abuse.ch hands out URLhaus's RPZ file only with an *Auth-Key*, which is free:

1. Log in at [auth.abuse.ch](https://auth.abuse.ch/) and copy your Auth-Key.
2. The URLhaus API page lists the RPZ file's download URL once you are logged in. In the
   blocklist's URL, put `{key}` where the key goes, for example
   `https://urlhaus-api.abuse.ch/v2/files/exports/{key}/<file>`.
3. Paste the key under *Key*. It is stored on the firewall and never shown again; leave
   the field empty to keep it.

A URL with a key must use `https://`. A zip download works as well.

## Allowed names

When a list blocks a site you need, add its domain under *Allowed names* below the
table and commit. An allowed domain, and every name below it, is never blocked by any
list. This is better than turning the whole list off.

## What blocked a name

BIND logs each blocked query. *Dashboard → Services → Show logs*, unit named (the DNS
server of the virtual firewall), shows lines like:

```
client 192.168.1.23#53312 (bad.example): rpz QNAME NXDOMAIN rewrite bad.example/A/IN via bad.example.hagezi-tif.rpz.invalid
```

The last part names the list (`hagezi-tif`). With *Log only* the line starts with
`disabled rpz`.

## Other lists

Any list served over http(s) works, with *Blocklist* left at *None*. One to four URLs
are read into one list. A download may be:

- an RPZ zone file, as the lists above serve. Only its block records count (`CNAME .`,
  `CNAME *.`, `rpz-drop.`). Redirects, passthru records and IP triggers are skipped.
- a list of domains, one per line, or adblock style `||domain^`.
- a hosts file: `0.0.0.0 domain`.

`#` and `;` start comments. A download that holds entries but no domain (an HTML error
page, say) fails, and the last good list stays in force. Each name is checked before it
reaches BIND, so a list can't do anything but block names.

## Memory

Every entry costs BIND memory, in each virtual firewall that uses the list, on both
hosts of an HA pair: about 500 MB per million entries. Hagezi's TIF mini (some 425 000
entries) takes about 230 MB, the full list over 2 GB. Watch the memory on the dashboard
after adding a large list.
