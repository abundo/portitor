// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { addressObjects, ipLists } from '@/api'

// Named hosts and prefixes, offered as suggestions in address fields, and
// IP lists, which rules take as "@name".
export const useObjectStore = defineStore('objects', {
  state: () => ({ list: [], ipLists: [], loaded: false }),
  getters: {
    names: (s) => s.list.map((o) => o.name),
    listRefs: (s) => s.ipLists.map((l) => `@${l.name}`),
  },
  actions: {
    async load(force = false) {
      if (this.loaded && !force) return
      ;[this.list, this.ipLists] = await Promise.all([addressObjects.list(), ipLists.list()])
      this.loaded = true
    },
  },
})
