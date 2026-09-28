// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { reactive, watch } from 'vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'

// The agent's log, polled while the panel is open. State is shared so the
// top bar's toggle and the panel see the same thing; whether it is open
// and its height are remembered in the browser.
const MAX_LINES = 2000
const POLL_MS = 2000
const RETRY_MS = 5000
const MIN_HEIGHT = 120

function load(key, fallback) {
  try {
    const v = localStorage.getItem(key)
    return v == null ? fallback : JSON.parse(v)
  } catch {
    return fallback
  }
}

function save(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // Not remembered; the panel works without it.
  }
}

const state = reactive({
  open: load('logPanel.open', false),
  height: load('logPanel.height', 240),
  lines: [],
  after: 0,
  error: null,
  paused: false,
})

watch(
  () => state.open,
  (v) => save('logPanel.open', v),
)

let timer = null
let running = false

async function poll() {
  timer = null
  if (!running) return
  let delay = POLL_MS
  try {
    const res = await api.agentLogs(state.after)
    state.error = null
    const entries = res.entries ?? []
    if (entries.length) {
      state.lines.push(...entries)
      if (state.lines.length > MAX_LINES) state.lines.splice(0, state.lines.length - MAX_LINES)
      state.after = entries.at(-1).id
    }
  } catch (err) {
    state.error = errMsg(err)
    delay = RETRY_MS
  }
  if (running) timer = setTimeout(poll, delay)
}

function maxHeight() {
  return Math.max(MIN_HEIGHT, Math.floor(window.innerHeight * 0.8))
}

export function useLogPanel() {
  return {
    state,
    toggle: () => (state.open = !state.open),
    close: () => (state.open = false),
    clear: () => (state.lines = []),
    togglePause: () => (state.paused = !state.paused),
    setHeight(h, persist = false) {
      state.height = Math.min(maxHeight(), Math.max(MIN_HEIGHT, Math.round(h)))
      if (persist) save('logPanel.height', state.height)
    },
    start() {
      if (running) return
      running = true
      poll()
    },
    stop() {
      running = false
      clearTimeout(timer)
      timer = null
    },
  }
}
