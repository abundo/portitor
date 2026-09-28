// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { computed, ref, watch } from 'vue'
import { interfaceZones, interfaces, links } from '@/api'
import { useInstanceStore } from '@/stores/instances'

// Interfaces and interface zones of the selected instance, as select items,
// id -> name lookups and the names rules may list.
export function useInstanceRefs() {
  const store = useInstanceStore()
  const ifaceZoneList = ref([])
  const ifaceList = ref([])
  const linkList = ref([])

  async function load() {
    if (!store.currentId) return
    const params = { instance_id: store.currentId }
    ;[ifaceZoneList.value, ifaceList.value, linkList.value] = await Promise.all([
      interfaceZones.list(params),
      interfaces.list(params),
      links.list(),
    ])
  }
  watch(() => store.currentId, load, { immediate: true })

  const ifaceItems = computed(() => ifaceList.value.map((i) => ({ label: i.name, value: i.id })))
  const ifaceName = (id) => ifaceList.value.find((i) => i.id === id)?.name ?? ''

  // Interface names of the instance: its interfaces and its link ends.
  const ifaceNames = computed(() => {
    const id = store.currentId
    const ends = linkList.value.flatMap((l) => [
      ...(l.instance_a_id === id ? [l.interface_a] : []),
      ...(l.instance_b_id === id ? [l.interface_b] : []),
    ])
    return [...new Set([...ifaceList.value.map((i) => i.name), ...ends])].sort()
  })
  // What a rule's interface list may hold: interface zones, then interfaces.
  const ifaceRefNames = computed(() => [
    ...ifaceZoneList.value.map((z) => z.name),
    ...ifaceNames.value,
  ])
  // The same as select items ({ label, value, description }), so pickers can
  // show each interface's and zone's description next to its name.
  const ifaceRefItems = computed(() => {
    const id = store.currentId
    const desc = new Map(ifaceList.value.map((i) => [i.name, i.description]))
    for (const l of linkList.value) {
      if (l.instance_a_id === id) desc.set(l.interface_a, l.description)
      if (l.instance_b_id === id) desc.set(l.interface_b, l.description)
    }
    return [
      ...ifaceZoneList.value.map((z) => ({
        label: z.name,
        value: z.name,
        description: z.description ? `zone: ${z.description}` : 'zone',
      })),
      ...ifaceNames.value.map((n) => ({ label: n, value: n, description: desc.get(n) || '' })),
    ]
  })
  const zonesOf = (name) =>
    ifaceZoneList.value.filter((z) => z.interfaces?.includes(name)).map((z) => z.name)

  return {
    store,
    ifaceZoneList,
    ifaceList,
    ifaceItems,
    ifaceName,
    ifaceNames,
    ifaceRefNames,
    ifaceRefItems,
    zonesOf,
    reload: load,
  }
}

export const actionColor = { accept: 'success', drop: 'error', reject: 'warning' }

// ifaceListLabel renders a rule's interface list; empty matches any interface.
export const ifaceListLabel = (list) => (list?.length ? list.join(', ') : 'any')
