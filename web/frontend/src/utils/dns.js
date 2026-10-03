// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

export const zoneTypes = [
  { label: 'Forward (names)', value: 'forward' },
  { label: 'Reverse IPv4 (PTR, generated)', value: 'reverse4' },
  { label: 'Reverse IPv6 (PTR, generated)', value: 'reverse6' },
  { label: 'Forward only (to other DNS servers)', value: 'forward-only' },
]

// What a zone without a DNS template gets (internal/render/dns.go).
export const builtinTemplate = {
  default_ttl: 300,
  nameservers: [{ name: 'localhost', address: '' }],
  soa: {
    mname: 'localhost',
    rname: 'hostmaster.localhost',
    refresh: 3600,
    retry: 600,
    expire: 604800,
    minimum: 300,
  },
}
