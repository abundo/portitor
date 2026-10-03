// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { computed, ref, watch } from 'vue'
import { asPathLists, communityLists, prefixLists, routeMaps } from '@/api'
import { useInstanceStore } from '@/stores/instances'

// The routing objects of the selected instance (prefix lists, AS path and
// community lists, route maps), as select items for the forms that refer
// to them by name. reload() after one changes.
export function useRoutingObjects() {
  const store = useInstanceStore()
  const prefix = ref([])
  const asPath = ref([])
  const community = ref([])
  const maps = ref([])

  async function reload() {
    if (!store.currentId) return
    const params = { instance_id: store.currentId }
    ;[prefix.value, asPath.value, community.value, maps.value] = await Promise.all([
      prefixLists.list(params),
      asPathLists.list(params),
      communityLists.list(params),
      routeMaps.list(params),
    ])
  }
  watch(() => store.currentId, reload, { immediate: true })

  const item = (o, extra = '') => ({
    label: o.name,
    value: o.name,
    description: [extra, o.description].filter(Boolean).join(' — '),
  })
  // prefixListItems(family): the prefix lists of that IP version, or all.
  const prefixListItems = (family) =>
    prefix.value
      .filter((l) => !family || l.family === family)
      .map((l) => item(l, l.family === 'ipv6' ? 'IPv6' : 'IPv4'))
  const asPathItems = computed(() => asPath.value.map((l) => item(l)))
  const communityItems = computed(() =>
    community.value.map((l) => item(l, l.kind.startsWith('large') ? 'large' : '')),
  )
  const routeMapItems = computed(() => maps.value.map((m) => item(m)))

  return { reload, prefixListItems, asPathItems, communityItems, routeMapItems }
}
