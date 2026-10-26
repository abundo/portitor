// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Public blocklists of bad actors, free and without an account, that an
// IP list (source url) reads as served: internal/iplist ParseText takes
// plain text, DShield's ranges and Spamhaus's JSON lines.
export const ipListFeeds = [
  {
    key: 'spamhaus-drop',
    label: 'Spamhaus DROP (IPv4)',
    url: 'https://www.spamhaus.org/drop/drop_v4.json',
    description:
      'Spamhaus DROP: hijacked netblocks and ranges run by criminals. Very few false positives.',
  },
  {
    key: 'spamhaus-dropv6',
    label: 'Spamhaus DROPv6 (IPv6)',
    url: 'https://www.spamhaus.org/drop/drop_v6.json',
    description: 'Spamhaus DROPv6: the IPv6 netblocks of DROP.',
  },
  {
    key: 'firehol-level1',
    label: 'FireHOL level 1',
    url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    description:
      'FireHOL level 1: Spamhaus DROP, Feodo, DShield and the bogons, private ranges included.',
    note: 'Holds the private ranges (10.0.0.0/8, 192.168.0.0/16, ...): use it only on traffic from the Internet, never on your own networks.',
  },
  {
    key: 'feodo',
    label: 'abuse.ch Feodo Tracker (botnet C2)',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
    description:
      'abuse.ch Feodo Tracker: botnet command and control servers. Best as a destination, to stop infected hosts calling home.',
  },
  {
    key: 'dshield',
    label: 'DShield top 20 attackers',
    url: 'https://feeds.dshield.org/block.txt',
    description: 'DShield recommended block list: the 20 /24 networks attacking most.',
  },
  {
    key: 'cins-army',
    label: 'CINS Army',
    url: 'https://cinsscore.com/list/ci-badguys.txt',
    description: 'CINS Army: addresses with a poor reputation score. Larger, more false positives.',
  },
  {
    key: 'et-block',
    label: 'Emerging Threats block IPs',
    url: 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
    description: 'Emerging Threats: compromised hosts, DShield and Spamhaus DROP.',
  },
  {
    key: 'blocklist-de',
    label: 'blocklist.de (all)',
    url: 'https://lists.blocklist.de/lists/all.txt',
    description:
      'blocklist.de: hosts that attacked SSH, mail, web and other services in the last 48 hours.',
    note: 'Changes by the hour: a refresh every few hours keeps it current.',
  },
]

// nightlySchedule returns a daily schedule at a random time between 02:00
// and 04:59, so firewalls don't all fetch a list at the same moment.
export function nightlySchedule() {
  const minute = Math.floor(Math.random() * 60)
  const hour = 2 + Math.floor(Math.random() * 3)
  return `${minute} ${hour} * * *`
}
