// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ref } from 'vue'

// How times are shown, the user's setting (date_format, set by the auth
// store): 'locale' follows the browser's language, 'iso' is YYYY-MM-DD,
// 'mdy' MM-DD-YYYY and 'dmy' DD-MM-YYYY, each with HH:MM:SS. A ref, so the
// pages that format times render again when it changes.
export const dateFormat = ref('locale')

const pad = (n, w = 2) => String(n).padStart(w, '0')

function hhmm(d, seconds) {
  const s = `${pad(d.getHours())}:${pad(d.getMinutes())}`
  return seconds ? `${s}:${pad(d.getSeconds())}` : s
}

function iso(d, seconds) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hhmm(d, seconds)}`
}

// fixed renders d in one of the fixed formats, or null for 'locale'.
function fixed(d, seconds) {
  const y = d.getFullYear()
  const m = pad(d.getMonth() + 1)
  const day = pad(d.getDate())
  switch (dateFormat.value) {
    case 'iso':
      return iso(d, seconds)
    case 'mdy':
      return `${m}-${day}-${y} ${hhmm(d, seconds)}`
    case 'dmy':
      return `${day}-${m}-${y} ${hhmm(d, seconds)}`
  }
  return null
}

// ago renders how long ago t (an ISO time) was, or 'never'.
export function ago(t) {
  if (!t) return 'never'
  const s = Math.round((Date.now() - new Date(t).getTime()) / 1000)
  if (s < 120) return `${s}s ago`
  if (s < 7200) return `${Math.round(s / 60)}m ago`
  if (s < 172800) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

// datetime renders a time as a local date and time with seconds.
export function datetime(t) {
  if (!t) return ''
  const d = new Date(t)
  return fixed(d, true) ?? d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' })
}

// when renders a time as a short local date and time, to the minute.
export function when(t) {
  if (!t) return ''
  const d = new Date(t)
  return fixed(d, false) ?? d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
}

// logTime renders a time for a log line: always YYYY-MM-DD HH:MM:SS.mmm,
// so lines line up whatever the setting.
export function logTime(t) {
  const d = new Date(t)
  return `${iso(d, true)}.${pad(d.getMilliseconds(), 3)}`
}

// clock renders a time of day with seconds.
export function clock(t) {
  if (!t) return ''
  const d = new Date(t)
  if (dateFormat.value !== 'locale') return hhmm(d, true)
  return d.toLocaleTimeString(undefined, { timeStyle: 'medium' })
}
