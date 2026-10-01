// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { api } from '@/api'

// Agent status, polled every 30 s, every 5 s while a page showing it is open
// and visible (watch/unwatch), and every 3 s while a change awaits confirmation so the
// banner can count down and the rollback is noticed. changes says whether
// the database differs from what is deployed. rates keeps each interface's
// receive and send rate (bytes/s) over the last 5 minutes, from the counters'
// differences between polls, by "instance/interface".
const RATE_WINDOW = 5 * 60 * 1000

export const useDeployStore = defineStore('deploy', {
  state: () => ({
    status: null,
    error: null,
    timer: null,
    changes: null,
    changesTimer: null,
    watchers: 0,
    rates: {},
    counters: {},
  }),
  getters: {
    pending: (s) => s.status?.pending ?? null,
    // Physical interfaces in the configuration that the firewall lacks.
    missingNics: (s) => s.status?.nic_sync?.missing ?? [],
  },
  actions: {
    async refresh() {
      try {
        this.status = await api.agentStatus()
        this.error = null
        this.sample()
      } catch (err) {
        this.error = err.response?.data?.error ?? err.message
      }
      this.checkChanges()
      this.schedule()
    },
    sample() {
      const now = Date.now()
      const seen = new Set()
      for (const inst of this.status?.instances ?? []) {
        for (const i of inst.interfaces ?? []) {
          const key = `${inst.name}/${i.name}`
          seen.add(key)
          const prev = this.counters[key]
          this.counters[key] = { t: now, rx: i.rx_bytes, tx: i.tx_bytes }
          const list = (this.rates[key] ?? []).filter((r) => now - r.t <= RATE_WINDOW)
          // A counter that went down was reset (interface recreated): no rate.
          if (prev && i.rx_bytes >= prev.rx && i.tx_bytes >= prev.tx && now > prev.t) {
            const s = (now - prev.t) / 1000
            list.push({ t: now, rx: (i.rx_bytes - prev.rx) / s, tx: (i.tx_bytes - prev.tx) / s })
          }
          this.rates[key] = list
        }
      }
      for (const key of Object.keys(this.counters)) {
        if (!seen.has(key)) {
          delete this.counters[key]
          delete this.rates[key]
        }
      }
    },
    async checkChanges() {
      try {
        this.changes = await api.deployChanges()
      } catch {
        // Keep the last answer; the next poll or edit tries again.
      }
    },
    // A burst of writes (a reorder, a zone save) checks once.
    changed() {
      clearTimeout(this.changesTimer)
      this.changesTimer = setTimeout(() => this.checkChanges(), 300)
    },
    schedule() {
      clearTimeout(this.timer)
      const fast = this.watchers && document.visibilityState === 'visible'
      const ms = this.pending ? 3000 : fast ? 5000 : 30000
      this.timer = setTimeout(() => this.refresh(), ms)
    },
    watch() {
      if (!this.watchers++) document.addEventListener('visibilitychange', this.onVisible)
      this.refresh()
    },
    unwatch() {
      if (!--this.watchers) document.removeEventListener('visibilitychange', this.onVisible)
      this.schedule()
    },
    // A watched page coming back into view refreshes at once.
    onVisible() {
      if (document.visibilityState === 'visible') this.refresh()
    },
  },
})
