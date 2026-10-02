// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Addresses as BigInt, to work out a DHCP range inside a prefix.

function parse4(s) {
  const parts = s.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null
  return parts.reduce((a, n) => (a << 8n) | BigInt(n), 0n)
}

function parse6(s) {
  const [head, tail, extra] = s.split('::')
  if (extra !== undefined) return null
  const groups = (x) => (x ? x.split(':') : [])
  const h = groups(head)
  const t = tail === undefined ? [] : groups(tail)
  const fill = 8 - h.length - t.length
  if (fill < 0 || (tail === undefined && fill !== 0)) return null
  const all = [...h, ...Array(fill).fill('0'), ...t]
  if (all.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null
  return all.reduce((a, g) => (a << 16n) | BigInt(parseInt(g, 16)), 0n)
}

function format4(n) {
  return [24n, 16n, 8n, 0n].map((s) => (n >> s) & 255n).join('.')
}

function format6(n) {
  const g = [112n, 96n, 80n, 64n, 48n, 32n, 16n, 0n].map((s) => ((n >> s) & 0xffffn).toString(16))
  // The longest run of zero groups becomes ::.
  let best = [-1, 0]
  for (let i = 0; i < 8; ) {
    let j = i
    while (j < 8 && g[j] === '0') j++
    if (j - i > best[1] && j - i > 1) best = [i, j - i]
    i = j === i ? i + 1 : j
  }
  if (best[0] < 0) return g.join(':')
  return `${g.slice(0, best[0]).join(':')}::${g.slice(best[0] + best[1]).join(':')}`
}

// suggestDhcpRange returns [start, end] for a DHCP range in cidr that
// leaves out the firewall's address fwAddr (a CIDR or plain address), or
// null. IPv4: .100-.199 in a /24 or larger, else the half of the prefix
// without fwAddr. IPv6: ::1000-::1fff.
export function suggestDhcpRange(cidr, fwAddr = '') {
  const [addr, len] = cidr.split('/')
  const bits = Number(len)
  const v6 = addr.includes(':')
  const width = v6 ? 128n : 32n
  const base = v6 ? parse6(addr) : parse4(addr)
  if (base === null || !Number.isInteger(bits) || BigInt(bits) > width) return null
  const fmt = v6 ? format6 : format4
  const fw = fwAddr ? (v6 ? parse6 : parse4)(fwAddr.split('/')[0]) : null
  const size = 1n << (width - BigInt(bits))
  const net = base & ~(size - 1n)
  const outside = (s, e) => fw === null || fw < s || fw > e
  if (v6) {
    if (size < 0x2000n) return null
    const s = net + 0x1000n
    const e = net + 0x1fffn
    return outside(s, e) ? [fmt(s), fmt(e)] : [fmt(net + 0x2000n), fmt(net + 0x2fffn)]
  }
  if (size < 4n) return null
  if (size >= 256n && outside(net + 100n, net + 199n)) return [fmt(net + 100n), fmt(net + 199n)]
  const mid = net + size / 2n
  const last = net + size - 2n // the last host, before the broadcast address
  if (outside(mid, last)) return [fmt(mid), fmt(last)]
  return [fmt(net + 1n), fmt(mid - 1n)]
}
