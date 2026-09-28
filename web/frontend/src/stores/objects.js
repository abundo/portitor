// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { addressObjects, api, customServices, ipLists } from '@/api'

// Named hosts and prefixes, offered as suggestions in address fields, and
// IP lists, which rules take as "@name", and the port names port fields
// accept: the built-in services and the custom ones; and the ICMP and
// ICMPv6 types rules match ({ icmp: [...], icmpv6: [...] }, fwconfig.ICMPTypes).
export const useObjectStore = defineStore('objects', {
  state: () => ({
    list: [],
    ipLists: [],
    services: [],
    customServices: [],
    icmpTypes: { icmp: [], icmpv6: [] },
    loaded: false,
  }),
  getters: {
    names: (s) => s.list.map((o) => o.name),
    listRefs: (s) => s.ipLists.map((l) => `@${l.name}`),
    // portNames: the custom services, then the built-in ones, as
    // { name, port, description, custom }; port is a number or, for a
    // custom service, its port list ("8000-8080", "80, 443").
    portNames: (s) => [
      ...s.customServices.map((c) => ({
        name: c.name,
        port: c.ports,
        description: c.description,
        custom: true,
      })),
      ...s.services,
    ],
  },
  actions: {
    async load(force = false) {
      if (this.loaded && !force) return
      ;[this.list, this.ipLists, this.services, this.customServices, this.icmpTypes] =
        await Promise.all([
          addressObjects.list(),
          ipLists.list(),
          api.services(),
          customServices.list(),
          api.icmpTypes(),
        ])
      this.loaded = true
    },
  },
})
