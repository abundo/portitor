// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { addressObjects, api, customServices, ipLists } from '@/api'
import { serviceSummary } from '@/utils/services'

// Named hosts and prefixes, offered as suggestions in address fields, and
// IP lists, which rules take as "@name"; the services rules name, custom
// and predefined; the built-in port names NAT port fields accept; and the
// ICMP and ICMPv6 types services match ({ icmp: [...], icmpv6: [...] },
// fwconfig.ICMPTypes).
export const useObjectStore = defineStore('objects', {
  state: () => ({
    list: [],
    ipLists: [],
    services: [],
    customServices: [],
    predefinedServices: [],
    icmpTypes: { icmp: [], icmpv6: [] },
    loaded: false,
  }),
  getters: {
    names: (s) => s.list.map((o) => o.name),
    listRefs: (s) => s.ipLists.map((l) => `@${l.name}`),
    // portNames: the built-in port names, as { name, port, description }.
    portNames: (s) => s.services,
    // allServices: the custom services, then the predefined ones (with
    // predefined: true), by name.
    allServices: (s) => [
      ...[...s.customServices].sort((a, b) => a.name.localeCompare(b.name)),
      ...s.predefinedServices.map((p) => ({ ...p, predefined: true })),
    ],
    // serviceItems: allServices for a select ({ label, value, description,
    // service }); the description shows what the service matches.
    serviceItems() {
      return this.allServices.map((svc) => ({
        label: svc.name,
        value: svc.name,
        description: [serviceSummary(svc), svc.description].filter(Boolean).join(' — '),
        service: svc,
      }))
    },
    serviceByName() {
      return new Map(this.allServices.map((svc) => [svc.name, svc]))
    },
  },
  actions: {
    async load(force = false) {
      if (this.loaded && !force) return
      ;[
        this.list,
        this.ipLists,
        this.services,
        this.customServices,
        this.predefinedServices,
        this.icmpTypes,
      ] = await Promise.all([
        addressObjects.list(),
        ipLists.list(),
        api.services(),
        customServices.list(),
        api.predefinedServices(),
        api.icmpTypes(),
      ])
      this.loaded = true
    },
  },
})
