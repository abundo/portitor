// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { addressObjects } from '@/api'

// Named hosts and prefixes, offered as suggestions in address fields.
export const useObjectStore = defineStore('objects', {
  state: () => ({ list: [], loaded: false }),
  getters: {
    names: (s) => s.list.map((o) => o.name),
  },
  actions: {
    async load(force = false) {
      if (this.loaded && !force) return
      this.list = await addressObjects.list()
      this.loaded = true
    },
  },
})
