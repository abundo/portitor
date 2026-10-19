// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { firewalls, instances } from '@/api'

const KEY = 'fw:instance'

// The instance selected in the top bar; most pages show that instance.
// firewalls are the hosts, for those who may read them (not a user without
// a global role); with several, an instance's name says which it is on.
export const useInstanceStore = defineStore('instances', {
  state: () => ({ list: [], firewalls: [], currentId: Number(localStorage.getItem(KEY)) || null }),
  getters: {
    current: (s) => s.list.find((i) => i.id === s.currentId) ?? null,
    items: (s) =>
      s.list.map((i) => {
        const fw =
          s.firewalls.length > 1 && !i.is_default
            ? s.firewalls.find((f) => f.id === i.firewall_id)
            : null
        const label = i.is_default ? `${i.name} (default)` : fw ? `${i.name} (${fw.name})` : i.name
        return { label, value: i.id }
      }),
    // topItems are the top bar's choice: with several firewalls, a group
    // per firewall under its name, its host first and its virtual
    // firewalls indented under it.
    topItems: (s) => {
      const hosts = s.firewalls.filter((f) => s.list.some((i) => i.firewall_id === f.id))
      if (hosts.length < 2) return s.list.map((i) => ({ label: i.name, value: i.id }))
      return hosts.map((f) => {
        const vfs = s.list.filter((i) => i.firewall_id === f.id)
        const host = vfs.find((i) => i.is_default)
        return [
          { type: 'label', label: f.name },
          ...(host
            ? [
                {
                  label: `${host.name} (host${f.config_url ? ', read-only here' : ''})`,
                  value: host.id,
                },
              ]
            : []),
          ...vfs
            .filter((i) => !i.is_default)
            .map((i) => ({ label: i.name, value: i.id, class: 'ps-6' })),
        ]
      })
    },
    // currentText names the selected one with its firewall when there are
    // several.
    currentText: (s) => {
      const cur = s.list.find((i) => i.id === s.currentId)
      if (!cur) return ''
      const hosts = s.firewalls.filter((f) => s.list.some((i) => i.firewall_id === f.id))
      const fw = s.firewalls.find((f) => f.id === cur.firewall_id)
      return hosts.length > 1 && fw ? `${fw.name} / ${cur.name}` : cur.name
    },
    nameOf: (s) => (id) => s.list.find((i) => i.id === id)?.name ?? '',
    // hasPeer: the selected VF runs on an HA pair, so what differs between
    // the hosts has a value for the secondary too.
    hasPeer: (s) => {
      const id = s.list.find((i) => i.id === s.currentId)?.firewall_id
      return !!id && s.firewalls.some((f) => f.ha_primary_id === id)
    },
    firewallItems: (s) => s.firewalls.map((f) => ({ label: f.name, value: f.id })),
    firewallName: (s) => (id) => s.firewalls.find((f) => f.id === id)?.name ?? '',
  },
  actions: {
    async load() {
      ;[this.list, this.firewalls] = await Promise.all([
        instances.list(),
        firewalls.list().catch(() => []),
      ])
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
