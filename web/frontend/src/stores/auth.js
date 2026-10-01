// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { api } from '@/api'
import { useInstanceStore } from '@/stores/instances'

export const useAuthStore = defineStore('auth', {
  state: () => ({ user: null, loaded: false }),
  getters: {
    isAuthenticated: (s) => s.user !== null,
    // A global admin changes everything. A global viewer reads everything;
    // a user with role 'none' only the instances their roles grant.
    isAdmin: (s) => s.user?.role === 'admin',
    readsAll: (s) => s.user?.role === 'admin' || s.user?.role === 'viewer',
    // levelOf(id): 'admin', 'viewer' or '' on an instance. The server
    // checks the same; this only hides what would be refused.
    levelOf: (s) => (id) => {
      if (s.user?.role === 'admin') return 'admin'
      const level = s.user?.access?.[id] ?? ''
      return level || (s.user?.role === 'viewer' ? 'viewer' : '')
    },
    // canEdit: an admin of the instance selected in the top bar.
    canEdit() {
      return this.levelOf(useInstanceStore().currentId) === 'admin'
    },
    // canDeploy: a global admin, or the admin of an instance (who deploys
    // just their instances).
    canDeploy: (s) =>
      s.user?.role === 'admin' || Object.values(s.user?.access ?? {}).includes('admin'),
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
    async login(username, password, remember) {
      this.user = await api.login(username, password, remember)
    },
    async updateProfile(body) {
      this.user = await api.updateMe(body)
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
