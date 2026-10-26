// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Public DNS blocklists in RPZ format that a DNS blocklist reads as
// served (internal/dnsblocklist Parse). refresh is in minutes.
export const dnsBlocklistFeeds = [
  {
    key: 'hagezi-tif',
    label: 'Hagezi Threat Intelligence Feeds (full)',
    urls: [
      'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/tif-1.txt',
      'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/tif-2.txt',
    ],
    refresh: 360,
    description: 'Hagezi TIF: malware, phishing, scams, cryptojacking and command and control.',
    note: 'Over 4 million entries, in two files: BIND needs gigabytes of memory for it. On a small firewall take the medium or mini version.',
  },
  {
    key: 'hagezi-tif-medium',
    label: 'Hagezi Threat Intelligence Feeds (medium)',
    urls: ['https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/tif.medium.txt'],
    refresh: 360,
    description: 'Hagezi TIF medium: the most important threat feeds, about 900 000 entries.',
  },
  {
    key: 'hagezi-tif-mini',
    label: 'Hagezi Threat Intelligence Feeds (mini)',
    urls: ['https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/tif.mini.txt'],
    refresh: 360,
    description: 'Hagezi TIF mini: the medium list cut to size, about 400 000 entries.',
  },
  {
    key: 'hagezi-pro',
    label: 'Hagezi Multi PRO (ads, trackers and threats)',
    urls: ['https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/pro.txt'],
    refresh: 360,
    description: 'Hagezi Multi PRO: ads, trackers, telemetry, phishing, malware and scams.',
    note: 'Blocks ads and trackers too, not only threats: now and then a site needs an allowed name.',
  },
  {
    key: 'urlhaus',
    label: 'abuse.ch URLhaus (malware sites)',
    urls: ['https://urlhaus-api.abuse.ch/v2/files/exports/{key}/'],
    refresh: 10,
    description: 'abuse.ch URLhaus: hosts that serve malware, updated every 5 minutes.',
    note: 'Needs a free Auth-Key (auth.abuse.ch): enter it under Key. Complete the URL with the RPZ file name that the URLhaus API page lists once you are logged in; {key} stands for the key. A zip download works too.',
  },
  {
    key: 'oisd-big',
    label: 'OISD big',
    urls: ['https://big.oisd.nl/rpz'],
    refresh: 360,
    description: 'OISD big: ads, trackers, malware and phishing, with few false positives.',
  },
  {
    key: 'oisd-small',
    label: 'OISD small',
    urls: ['https://small.oisd.nl/rpz'],
    refresh: 360,
    description: 'OISD small: the most common ads, trackers and malware, about 120 000 entries.',
  },
  {
    key: 'oisd-nsfw',
    label: 'OISD NSFW (adult content)',
    urls: ['https://nsfw.oisd.nl/rpz'],
    refresh: 720,
    description: 'OISD NSFW: adult sites.',
  },
]
