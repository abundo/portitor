// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { config } from '@/api/config'

// The configuration's schema (GET /api/schema): the YANG modules compiled,
// which pages built on it (schemaFields) take their fields from.
export const useSchemaStore = defineStore('schema', {
  state: () => ({ root: null, loading: null }),
  actions: {
    async load() {
      if (this.root) return this.root
      this.loading ??= config.schema().then((r) => (this.root = r))
      return this.loading
    },
    // node is the schema node at a schema path, /instance/syslog-server.
    node(schemaPath) {
      let n = this.root
      for (const step of schemaPath.split('/').filter(Boolean)) {
        n = n?.children?.find((c) => c.name === step)
        if (!n) return null
      }
      return n
    },
  },
})
