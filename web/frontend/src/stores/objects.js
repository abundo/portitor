// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { addressLists, addressObjects, api, customServices, ipLists, portNames } from '@/api'
import { serviceSummary } from '@/utils/services'

// Named hosts and prefixes and address lists, offered as suggestions in
// address fields, and IP lists, which rules take as "@name"; the services rules name, custom
// and predefined; the port names NAT port fields accept, custom and built-in; and the
// ICMP and ICMPv6 types services match ({ icmp: [...], icmpv6: [...] },
// fwconfig.ICMPTypes).
export const useObjectStore = defineStore('objects', {
  state: () => ({
    list: [],
    addressLists: [],
    ipLists: [],
    services: [],
    customPortNames: [],
    customServices: [],
    predefinedServices: [],
    icmpTypes: { icmp: [], icmpv6: [] },
    loaded: false,
  }),
  getters: {
    names: (s) => [...s.list, ...s.addressLists].map((o) => o.name),
    listRefs: (s) => s.ipLists.map((l) => `@${l.name}`),
    // portNames: the custom port names, then the built-in ones, as
    // { name, port, description }.
    portNames: (s) => [
      ...[...s.customPortNames].sort((a, b) => a.name.localeCompare(b.name)),
      ...s.services,
    ],
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
        this.addressLists,
        this.ipLists,
        this.services,
        this.customPortNames,
        this.customServices,
        this.predefinedServices,
        this.icmpTypes,
      ] = await Promise.all([
        addressObjects.list(),
        addressLists.list(),
        ipLists.list(),
        api.services(),
        portNames.list(),
        customServices.list(),
        api.predefinedServices(),
        api.icmpTypes(),
      ])
      this.loaded = true
    },
  },
})
