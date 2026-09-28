// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { api } from '@/api'

// Agent status, polled every 30 s, every 5 s while a page showing it is open
// and visible (watch/unwatch), and every 3 s while a change awaits confirmation so the
// banner can count down and the rollback is noticed. changes says whether
// the database differs from what is deployed.
export const useDeployStore = defineStore('deploy', {
  state: () => ({
    status: null,
    error: null,
    timer: null,
    changes: null,
    changesTimer: null,
    watchers: 0,
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
      } catch (err) {
        this.error = err.response?.data?.error ?? err.message
      }
      this.checkChanges()
      this.schedule()
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
