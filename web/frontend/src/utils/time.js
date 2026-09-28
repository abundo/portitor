// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ref, watch } from 'vue'

// How times are shown: 'locale' follows the browser's language, 'iso' is
// always YYYY-MM-DD HH:MM:SS. Remembered in the browser; a ref, so the
// pages that format times render again when it changes.
const KEY = 'dateFormat'

function load() {
  try {
    return localStorage.getItem(KEY) === 'iso' ? 'iso' : 'locale'
  } catch {
    return 'locale'
  }
}

export const dateFormat = ref(load())

watch(dateFormat, (v) => {
  try {
    localStorage.setItem(KEY, v)
  } catch {
    // Not remembered; the setting holds until the page is reloaded.
  }
})

const pad = (n, w = 2) => String(n).padStart(w, '0')

function iso(d, seconds) {
  const s = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  return seconds ? `${s}:${pad(d.getSeconds())}` : s
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
  if (dateFormat.value === 'iso') return iso(d, true)
  return d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' })
}

// when renders a time as a short local date and time, to the minute.
export function when(t) {
  if (!t) return ''
  const d = new Date(t)
  if (dateFormat.value === 'iso') return iso(d, false)
  return d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
}

// logTime renders a time for a log line: always YYYY-MM-DD HH:MM:SS.mmm,
// so lines line up whatever the setting.
export function logTime(t) {
  const d = new Date(t)
  return `${iso(d, true)}.${pad(d.getMilliseconds(), 3)}`
}
