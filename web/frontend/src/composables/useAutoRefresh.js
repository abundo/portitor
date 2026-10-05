// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Automatic refresh (AGENTS.md, GUI design rules): calls load every
// `seconds` while active() is true and the tab is visible, for an hour from
// when it starts; then it stops until refresh() starts another hour. Shown
// with AutoRefreshButton.vue.
import { getCurrentScope, onScopeDispose, reactive, ref, watch } from 'vue'
import { useDeployStore } from '@/stores/deploy'

export const autoRefreshLimit = 3600 // seconds

export function useAutoRefresh(load, { seconds, active = () => true } = {}) {
  const state = reactive({ seconds, running: false, refresh })
  let timer = null
  let deadline = 0

  function stop() {
    clearTimeout(timer)
    timer = null
    state.running = false
  }
  function schedule() {
    clearTimeout(timer)
    timer = setTimeout(tick, seconds * 1000)
  }
  async function tick() {
    if (Date.now() >= deadline) return stop()
    if (!document.hidden) await load()
    if (state.running) schedule()
  }
  function start() {
    deadline = Date.now() + autoRefreshLimit * 1000
    state.running = true
    load()
    schedule()
  }
  // refresh loads now; stopped, it starts another hour.
  function refresh() {
    if (!active()) return load()
    if (!state.running) return start()
    load()
    schedule()
  }

  watch(active, (on) => (on ? start() : stop()), { immediate: true })
  if (getCurrentScope()) onScopeDispose(stop)
  return state
}

// The agent's status as the deploy store holds it (interfaces, WireGuard
// handshakes, DHCP client leases), refreshed every 5 s; loading is true
// while a refresh runs.
export function useStatusRefresh({ active } = {}) {
  const deploy = useDeployStore()
  const loading = ref(false)
  async function load() {
    loading.value = true
    try {
      await deploy.refresh()
    } finally {
      loading.value = false
    }
  }
  return { auto: useAutoRefresh(load, { seconds: 5, active }), loading }
}
