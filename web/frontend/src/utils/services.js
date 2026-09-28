// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Services (models.Service): a type, 'tcp/udp/sctp', 'icmp', 'icmp6' or
// 'ip', and the fields of that type: ports ([{ protocol, dst_lo, dst_hi,
// src_lo, src_hi }], a lo of 0 is any port, a hi of 0 is lo), icmp_type
// and icmp_code (empty or null is any), ip_protocol (0 is any).

export const serviceTypes = [
  { label: 'TCP/UDP/SCTP', value: 'tcp/udp/sctp' },
  { label: 'ICMP', value: 'icmp' },
  { label: 'ICMP6', value: 'icmp6' },
  { label: 'IP', value: 'ip' },
]

// portProtocols are the protocols of a 'tcp/udp/sctp' service's entries.
export const portProtocols = ['tcp', 'udp', 'sctp']

// A few IP protocol numbers by name, for the summary.
const ipProtocolNames = {
  1: 'icmp',
  6: 'tcp',
  17: 'udp',
  47: 'gre',
  50: 'esp',
  51: 'ah',
  58: 'icmpv6',
  89: 'ospf',
  112: 'vrrp',
  132: 'sctp',
}

function range(lo, hi) {
  if (!lo) return ''
  return !hi || hi === lo ? `${lo}` : `${lo}-${hi}`
}

// serviceMatches describes each match of a service in a few words:
// "tcp/443", "udp/53 from 1024-65535", "icmp echo-request code 0", "ip 47 (gre)".
export function serviceMatches(s) {
  switch (s.type) {
    case 'tcp/udp/sctp':
      return (s.ports ?? []).map((p) => {
        const dst = range(p.dst_lo, p.dst_hi)
        const src = range(p.src_lo, p.src_hi)
        return `${p.protocol}${dst ? `/${dst}` : ''}${src ? ` from ${src}` : ''}`
      })
    case 'icmp':
    case 'icmp6': {
      const code = s.icmp_code ?? null
      return [
        [s.type, s.icmp_type || 'any', code !== null ? `code ${code}` : '']
          .filter(Boolean)
          .join(' '),
      ]
    }
    case 'ip':
      if (!s.ip_protocol) return ['ip any']
      return [
        `ip ${s.ip_protocol}${ipProtocolNames[s.ip_protocol] ? ` (${ipProtocolNames[s.ip_protocol]})` : ''}`,
      ]
  }
  return []
}

export const serviceSummary = (s) => serviceMatches(s).join(', ')

// newService is an empty service of the first type, with one TCP entry.
export function newService(name = '') {
  return {
    name,
    description: '',
    type: 'tcp/udp/sctp',
    ports: [newPort()],
    icmp_type: '',
    icmp_code: null,
    ip_protocol: 0,
  }
}

export function newPort(protocol = 'tcp') {
  return { protocol, dst_lo: 0, dst_hi: 0, src_lo: 0, src_hi: 0 }
}
