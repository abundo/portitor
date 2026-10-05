// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { reactive, watch } from 'vue'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'
import { errMsg } from '@/api/http'

// The agent's log, the packets the rulesets logged and the queries the DNS
// servers logged, each a tab of the panel; the open tab is polled while the
// panel is open. State is shared so the top bar's toggle and the panel see
// the same thing; whether it is open, its tab and its height are
// remembered in the browser.
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

// A tab's entries and the id to poll after.
const feed = () => ({ lines: [], after: 0 })

const state = reactive({
  open: load('logPanel.open', false),
  height: load('logPanel.height', 240),
  tab: ['packets', 'dns'].includes(load('logPanel.tab', 'log'))
    ? load('logPanel.tab', 'log')
    : 'log',
  log: feed(),
  packets: feed(),
  dns: feed(),
  error: null,
  paused: false,
})

const fetchers = {
  // The agent's log tells of every instance: a global reader's only.
  log: (after) =>
    useAuthStore().readsAll ? api.agentLogs(after) : Promise.resolve({ entries: [] }),
  packets: (after) => api.agentPacketLog(after),
  dns: (after) => api.agentDnsQueryLog(after),
}

let timer = null
let running = false
let polling = 0 // generation, so a tab switch drops an answer in flight

watch(
  () => state.open,
  (v) => save('logPanel.open', v),
)
watch(
  () => state.tab,
  (v) => {
    save('logPanel.tab', v)
    // Catch up with the tab now rather than at the next poll.
    if (running) {
      clearTimeout(timer)
      poll()
    }
  },
)

async function poll() {
  timer = null
  if (!running) return
  const gen = ++polling
  const f = state[state.tab]
  let delay = POLL_MS
  try {
    const res = await fetchers[state.tab](f.after)
    if (gen !== polling) return
    state.error = null
    const entries = res.entries ?? []
    if (entries.length) {
      f.lines.push(...entries)
      if (f.lines.length > MAX_LINES) f.lines.splice(0, f.lines.length - MAX_LINES)
      f.after = entries.at(-1).id
    }
  } catch (err) {
    if (gen !== polling) return
    state.error = errMsg(err)
    delay = RETRY_MS
  }
  if (running) timer = setTimeout(poll, delay)
}

// The GUI's own messages (the toasts in the corner) go into the Agent log
// tab too, where they stay and can be copied. Their ids are strings, so
// they never collide with the agent's.
const toastLevels = { error: 'ERROR', warning: 'WARN' }
let noted = 0
function note(t) {
  const message = [t.title, t.description].filter(Boolean).join(': ')
  if (!message) return
  const f = state.log
  f.lines.push({
    id: `gui-${++noted}`,
    time: new Date().toISOString(),
    level: toastLevels[t.color] ?? 'INFO',
    message,
    attrs: { source: 'gui' },
  })
  if (f.lines.length > MAX_LINES) f.lines.splice(0, f.lines.length - MAX_LINES)
}

function maxHeight() {
  return Math.max(MIN_HEIGHT, Math.floor(window.innerHeight * 0.8))
}

export function useLogPanel() {
  return {
    state,
    note,
    toggle: () => (state.open = !state.open),
    close: () => (state.open = false),
    clear: () => (state[state.tab].lines = []),
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
