// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { computed, ref, watch } from 'vue'
import { vfApi } from '@/api/config'
import { useInstanceStore } from '@/stores/instances'

const vrfs = vfApi('vrf')

// The VRF the routing pages show (Routing, BGP, OSPF, IS-IS, BFD), by name:
// '' is the main table (no VRF). One choice for all of them, so it stays
// as the user goes from page to page; another virtual firewall starts at
// the main table.
const chosen = ref('')
let chosenFor = null

// ALL_VRFS is the "all VRFs" choice of a page that offers it (useVrfChoice
// with all), which keeps its own choice.
export const ALL_VRFS = '*'

export function useVrfChoice({ all = false } = {}) {
  const store = useInstanceStore()
  const vrfList = ref([])
  const vrf = all ? ref(ALL_VRFS) : chosen

  async function load() {
    if (!store.currentName) return
    vrfList.value = await vrfs.list()
    // A VRF deleted meanwhile.
    if (vrf.value && vrf.value !== ALL_VRFS && !vrfList.value.some((v) => v.name === vrf.value))
      vrf.value = ''
  }
  watch(
    () => store.currentName,
    (name) => {
      if (all) vrf.value = ALL_VRFS
      else if (chosenFor !== name) {
        chosen.value = ''
        chosenFor = name
      }
      load()
    },
    { immediate: true },
  )

  const vrfItems = computed(() => [
    ...(all ? [{ label: 'All VRFs', value: ALL_VRFS }] : []),
    { label: 'Main (no VRF)', value: '' },
    ...vrfList.value.map((v) => ({
      label: `VRF ${v.name} (table ${v.route_table})`,
      value: v.name,
    })),
  ])
  // current is the chosen VRF's row, null for the main table (or all).
  const current = computed(() => vrfList.value.find((v) => v.name === vrf.value) ?? null)
  // vrfName is the chosen VRF's name, '' for the main table.
  const vrfName = computed(() => current.value?.name ?? '')
  // vrfKey is the chosen VRF in the configuration tree's routing entries'
  // keys (bgp=main, ospf=2,blue): its name, or main; inVrfKey reports
  // whether such an entry (its vrf) is the chosen VRF's.
  const vrfKey = computed(() => vrfName.value || 'main')
  const inVrfKey = (row) => (row.vrf || 'main') === vrfKey.value
  // showsName reports whether a VRF name ('' for none) is shown.
  const showsName = (name) => vrf.value === ALL_VRFS || (name || '') === vrfName.value

  return {
    vrf,
    vrfList,
    vrfItems,
    current,
    vrfName,
    vrfKey,
    inVrfKey,
    showsName,
    reload: load,
  }
}
