// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { computed, ref, watch } from 'vue'
import { interfaces, zones } from '@/api'
import { useInstanceStore } from '@/stores/instances'

// Zones and interfaces of the selected instance, as select items and
// id -> name lookups.
export function useInstanceRefs() {
  const store = useInstanceStore()
  const zoneList = ref([])
  const ifaceList = ref([])

  async function load() {
    if (!store.currentId) return
    const params = { instance_id: store.currentId }
    ;[zoneList.value, ifaceList.value] = await Promise.all([
      zones.list(params),
      interfaces.list(params),
    ])
  }
  watch(() => store.currentId, load, { immediate: true })

  const zoneItems = computed(() => zoneList.value.map((z) => ({ label: z.name, value: z.id })))
  const ifaceItems = computed(() => ifaceList.value.map((i) => ({ label: i.name, value: i.id })))
  const zoneName = (id) => zoneList.value.find((z) => z.id === id)?.name ?? ''
  const ifaceName = (id) => ifaceList.value.find((i) => i.id === id)?.name ?? ''

  return { store, zoneList, ifaceList, zoneItems, ifaceItems, zoneName, ifaceName, reload: load }
}

export const actionColor = { accept: 'success', drop: 'error', reject: 'warning' }
