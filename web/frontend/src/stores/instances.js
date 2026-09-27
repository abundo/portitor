// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { instances } from '@/api'

const KEY = 'fw:instance'

// The instance selected in the top bar; most pages show that instance.
export const useInstanceStore = defineStore('instances', {
  state: () => ({ list: [], currentId: Number(localStorage.getItem(KEY)) || null }),
  getters: {
    current: (s) => s.list.find((i) => i.id === s.currentId) ?? null,
    items: (s) =>
      s.list.map((i) => ({ label: i.is_default ? `${i.name} (default)` : i.name, value: i.id })),
    nameOf: (s) => (id) => s.list.find((i) => i.id === id)?.name ?? '',
  },
  actions: {
    async load() {
      this.list = await instances.list()
      if (!this.list.some((i) => i.id === this.currentId)) {
        this.select(this.list.find((i) => i.is_default)?.id ?? this.list[0]?.id ?? null)
      }
    },
    select(id) {
      this.currentId = id
      if (id) localStorage.setItem(KEY, String(id))
    },
  },
})
