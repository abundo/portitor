<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// BgpFilterPick: a BGP neighbour's filter in one direction of one address
// family: none, a prefix list (v-model:list) or a route map (v-model:map),
// never both.
import { computed, ref, watch } from 'vue'
import NameSelect from '@/components/NameSelect.vue'

const list = defineModel('list', { type: String, default: '' })
const map = defineModel('map', { type: String, default: '' })
defineProps({
  prefixListItems: { type: Array, default: () => [] },
  routeMapItems: { type: Array, default: () => [] },
  disabled: { type: Boolean, default: false },
})

const kinds = [
  { label: 'No filter', value: 'none' },
  { label: 'Prefix list', value: 'list' },
  { label: 'Route map', value: 'map' },
]
// The kind is kept apart from the names, so it can be chosen before a name.
const kind = ref('none')
watch(
  [list, map],
  () => {
    if (map.value) kind.value = 'map'
    else if (list.value) kind.value = 'list'
  },
  { immediate: true },
)
watch(kind, (k) => {
  if (k !== 'list') list.value = ''
  if (k !== 'map') map.value = ''
})
const name = computed({
  get: () => (kind.value === 'map' ? map.value : list.value),
  set: (v) => (kind.value === 'map' ? (map.value = v) : (list.value = v)),
})
</script>

<template>
  <div class="flex w-full gap-2">
    <USelect v-model="kind" :items="kinds" class="w-36 shrink-0" :disabled="disabled" />
    <NameSelect
      v-if="kind !== 'none'"
      v-model="name"
      :items="kind === 'map' ? routeMapItems : prefixListItems"
      :disabled="disabled"
    />
  </div>
</template>
