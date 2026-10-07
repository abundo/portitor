// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// bytes renders a byte count with a binary unit: "1.5 MB".
export function bytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`
}

// bitRate renders a rate in bytes/s as bits/s with a decimal unit: "12.3 Mbit/s".
export function bitRate(bytesPerSec) {
  const u = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s']
  let n = bytesPerSec * 8
  let i = 0
  while (n >= 1000 && i < u.length - 1) {
    n /= 1000
    i++
  }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`
}
