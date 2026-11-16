// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { firewalls } from '@/api'
import { config, fromEntry, treeApi } from '@/api/config'

const KEY = 'fw:vf'

// The virtual firewalls (the configuration's instances, by name), without
// their nested lists; and the host, the default one, whose configuration is
// the top level (its name the leaf host-name), on the firewall that is no
// HA secondary.
const instanceList = treeApi(() => 'instance', ['name'], { shallow: true })

async function hostOf(fws) {
  const top = fromEntry(
    (await config.get('', 'candidate', { shallow: '' }).catch(() => null)) ?? {},
  )
  if (!top.host_name) return null
  const leaves = Object.fromEntries(
    Object.entries(top).filter(
      ([, v]) =>
        v === null ||
        typeof v !== 'object' ||
        (Array.isArray(v) && v.every((x) => typeof x !== 'object')),
    ),
  )
  const fw = fws.find((f) => !f.ha_primary_id)?.name ?? ''
  return { ...leaves, name: top.host_name, id: top.host_name, is_default: true, firewall: fw }
}

function stored() {
  try {
    return localStorage.getItem(KEY) || null
  } catch {
    return null
  }
}

// The virtual firewall selected in the top bar, by name; most pages show
// that one. firewalls are the hosts, for those who may read them (not a
// user without a global role); with several, a virtual firewall's name
// says which it is on. A virtual firewall's `firewall` is its firewall's
// name.
export const useInstanceStore = defineStore('instances', {
  state: () => ({ list: [], firewalls: [], currentName: stored() }),
  getters: {
    current: (s) => s.list.find((i) => i.name === s.currentName) ?? null,
    // hostName is the host's name ('' when it can't be read).
    hostName: (s) => s.list.find((i) => i.is_default)?.name ?? '',
    items: (s) =>
      s.list.map((i) => {
        const fw = s.firewalls.length > 1 && !i.is_default ? i.firewall : ''
        const label = i.is_default ? `${i.name} (default)` : fw ? `${i.name} (${fw})` : i.name
        return { label, value: i.name }
      }),
    // firewallId is the selected one's firewall's id (the firewalls are
    // rows of their own, with ids).
    firewallId: (s) => {
      const fw = s.list.find((i) => i.name === s.currentName)?.firewall
      return s.firewalls.find((f) => f.name === fw)?.id ?? null
    },
    // hostItems are the top bar's firewall choice: the firewalls with
    // virtual firewalls (an HA secondary has none of its own).
    hostItems: (s) =>
      s.firewalls
        .filter((f) => s.list.some((i) => i.firewall === f.name))
        .map((f) => ({ label: f.config_url ? `${f.name} (read-only here)` : f.name, value: f.id })),
    // topItems are the top bar's VF choice: the selected one's firewall's
    // virtual firewalls, its host first.
    topItems: (s) => {
      const fw = s.list.find((i) => i.name === s.currentName)?.firewall
      return s.list
        .filter((i) => i.firewall === fw)
        .sort((a, b) => b.is_default - a.is_default)
        .map((i) => ({ label: i.name, value: i.name }))
    },
    // host is the host of the selected one's firewall.
    host: (s) => {
      const fw = s.list.find((i) => i.name === s.currentName)?.firewall
      return s.list.find((i) => i.is_default && i.firewall === fw) ?? null
    },
    firewallItems: (s) => s.firewalls.map((f) => ({ label: f.name, value: f.id })),
    firewallName: (s) => (id) => s.firewalls.find((f) => f.id === id)?.name ?? '',
  },
  actions: {
    async load() {
      const [vfs, fws] = await Promise.all([instanceList.list(), firewalls.list().catch(() => [])])
      const host = await hostOf(fws)
      this.firewalls = fws
      this.list = host ? [host, ...vfs] : vfs
      if (!this.list.some((i) => i.name === this.currentName)) {
        this.select(this.list.find((i) => i.is_default)?.name ?? this.list[0]?.name ?? null)
      }
    },
    // selectFirewall selects a firewall's host, else its first virtual
    // firewall.
    selectFirewall(id) {
      const fw = this.firewalls.find((f) => f.id === id)?.name
      const vfs = this.list.filter((i) => i.firewall === fw)
      this.select((vfs.find((i) => i.is_default) ?? vfs[0])?.name ?? null)
    },
    select(name) {
      this.currentName = name
      try {
        if (name) localStorage.setItem(KEY, name)
      } catch {
        // The choice is only remembered for this page.
      }
    },
  },
})
