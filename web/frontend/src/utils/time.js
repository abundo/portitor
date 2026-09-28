// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// ago renders how long ago t (an ISO time) was, or 'never'.
export function ago(t) {
  if (!t) return 'never'
  const s = Math.round((Date.now() - new Date(t).getTime()) / 1000)
  if (s < 120) return `${s}s ago`
  if (s < 7200) return `${Math.round(s / 60)}m ago`
  if (s < 172800) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

// when renders a time as a short local date and time.
export function when(t) {
  if (!t) return ''
  return new Date(t).toLocaleString(undefined, {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}
