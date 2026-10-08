// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { computed, ref, watch } from 'vue'
import { vrfs } from '@/api'
import { useInstanceStore } from '@/stores/instances'

// The VRF the routing pages show (Routing, BGP, OSPF, IS-IS, BFD): 0 is
// the main table (no VRF), else a VRF's id. One choice for all of them, so
// it stays as the user goes from page to page; another virtual firewall
// starts at the main table.
const chosen = ref(0)
let chosenFor = null

// ALL_VRFS is the "all VRFs" choice of a page that offers it (useVrfChoice
// with all), which keeps its own choice.
export const ALL_VRFS = -1

export function useVrfChoice({ all = false } = {}) {
  const store = useInstanceStore()
  const vrfList = ref([])
  const vrf = all ? ref(ALL_VRFS) : chosen

  async function load() {
    if (!store.currentId) return
    vrfList.value = await vrfs.list({ instance_id: store.currentId })
    // A VRF deleted meanwhile.
    if (vrf.value > 0 && !vrfList.value.some((v) => v.id === vrf.value)) vrf.value = 0
  }
  watch(
    () => store.currentId,
    (id) => {
      if (all) vrf.value = ALL_VRFS
      else if (chosenFor !== id) {
        chosen.value = 0
        chosenFor = id
      }
      load()
    },
    { immediate: true },
  )

  const vrfItems = computed(() => [
    ...(all ? [{ label: 'All VRFs', value: ALL_VRFS }] : []),
    { label: 'Main (no VRF)', value: 0 },
    ...vrfList.value.map((v) => ({ label: `VRF ${v.name} (table ${v.route_table})`, value: v.id })),
  ])
  // current is the chosen VRF's row, null for the main table (or all).
  const current = computed(() => vrfList.value.find((v) => v.id === vrf.value) ?? null)
  // vrfName is the chosen VRF's name, '' for the main table.
  const vrfName = computed(() => current.value?.name ?? '')
  // vrfId is the vrf_id of the chosen VRF's rows: null for the main table.
  const vrfId = computed(() => current.value?.id ?? null)
  // ofVrf reports whether a routing row (vrf_id) is the chosen VRF's.
  const ofVrf = (row) => (row.vrf_id ?? null) === vrfId.value
  // showsName reports whether a VRF name ('' for none) is shown.
  const showsName = (name) => vrf.value === ALL_VRFS || (name || '') === vrfName.value

  return { vrf, vrfList, vrfItems, current, vrfName, vrfId, ofVrf, showsName, reload: load }
}
