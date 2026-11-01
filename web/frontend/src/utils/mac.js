// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// MAC addresses are shown as 1122.3344.5566. Inputs take that form,
// 11:22:33:44:55:66 and 11-22-33-44-55-66; the server stores them with colons.

// macHex returns the 12 lowercase hex digits of a MAC address in any of those
// forms, or null.
function macHex(value) {
  if (typeof value !== 'string') return null
  const s = value.trim().toLowerCase()
  if (
    !/^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/.test(s) &&
    !/^[0-9a-f]{4}(\.[0-9a-f]{4}){2}$/.test(s) &&
    !/^[0-9a-f]{12}$/.test(s)
  )
    return null
  return s.replace(/[:.-]/g, '')
}

export const isMacAddress = (value) => macHex(value) !== null

// formatMac shows a MAC address as 1122.3344.5566; anything else (empty, or
// not a MAC) is returned as it is.
export function formatMac(value) {
  const hex = macHex(value)
  if (!hex) return value ?? ''
  return `${hex.slice(0, 4)}.${hex.slice(4, 8)}.${hex.slice(8)}`
}
