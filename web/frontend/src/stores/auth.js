// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { api } from '@/api'

export const useAuthStore = defineStore('auth', {
  state: () => ({ user: null, loaded: false }),
  getters: {
    isAuthenticated: (s) => s.user !== null,
  },
  actions: {
    async fetchCurrentUser() {
      try {
        this.user = await api.me()
      } catch {
        this.user = null
      } finally {
        this.loaded = true
      }
    },
    async login(username, password) {
      this.user = await api.login(username, password)
    },
    async logout() {
      try {
        await api.logout()
      } finally {
        this.user = null
      }
    },
  },
})
