// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { api } from '@/api'

// Agent status, polled while a change awaits confirmation so the banner
// can count down and the rollback is noticed.
export const useDeployStore = defineStore('deploy', {
  state: () => ({ status: null, error: null, timer: null }),
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
      this.schedule()
    },
    schedule() {
      clearTimeout(this.timer)
      this.timer = setTimeout(() => this.refresh(), this.pending ? 3000 : 30000)
    },
  },
})
