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
    // firewallId is the selected one's firewall.
    firewallId: (s) => s.list.find((i) => i.id === s.currentId)?.firewall_id ?? null,
    // hostItems are the top bar's firewall choice: the firewalls with
    // instances (an HA secondary has none of its own).
    hostItems: (s) =>
      s.firewalls
        .filter((f) => s.list.some((i) => i.firewall_id === f.id))
        .map((f) => ({ label: f.config_url ? `${f.name} (read-only here)` : f.name, value: f.id })),
    // topItems are the top bar's VF choice: the selected one's firewall's
    // instances, its host first.
    topItems: (s) => {
      const fw = s.list.find((i) => i.id === s.currentId)?.firewall_id
      return s.list
        .filter((i) => i.firewall_id === fw)
        .sort((a, b) => b.is_default - a.is_default)
        .map((i) => ({ label: i.name, value: i.id }))
    },
    // host is the host of the selected one's firewall.
    host: (s) => {
      const fw = s.list.find((i) => i.id === s.currentId)?.firewall_id
      return s.list.find((i) => i.is_default && i.firewall_id === fw) ?? null
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
    // selectFirewall selects a firewall's host, else its first instance.
    selectFirewall(id) {
      const vfs = this.list.filter((i) => i.firewall_id === id)
      this.select((vfs.find((i) => i.is_default) ?? vfs[0])?.id ?? null)
    },
    select(id) {
      this.currentId = id
      if (id) localStorage.setItem(KEY, String(id))
    },
  },
})
