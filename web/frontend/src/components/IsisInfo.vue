<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// IsisInfo: IS-IS's state as FRR has it (agentapi.ISISInstance): the
// system id, then adjacencies, interfaces and routes.
import { computed } from 'vue'
import SearchInput from '@/components/SearchInput.vue'
import { useSearch, valuesText } from '@/utils/search'

const props = defineProps({
  // ISISInstance, or null when IS-IS is not running.
  state: { type: Object, default: null },
  // The answer came (a null state then means not running).
  loaded: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
})

const list = (k) => computed(() => props.state?.[k] ?? [])
const nbr = useSearch(list('neighbors'), (n) =>
  valuesText(n.system_id, n.interface, n.level, n.state, n.snpa),
)
const ifs = useSearch(list('interfaces'), (i) => valuesText(i.name, i.state, i.type, i.level))
const route = useSearch(list('routes'), (r) =>
  valuesText(r.prefix, r.level, r.next_hops, r.interfaces),
)

const stateColor = (s) => (s === 'Up' ? 'success' : s ? 'warning' : 'neutral')

const nbrColumns = [
  { accessorKey: 'system_id', header: 'Neighbour' },
  { accessorKey: 'interface', header: 'Interface' },
  { accessorKey: 'level', header: 'Level' },
  { accessorKey: 'state', header: 'State' },
  { accessorKey: 'hold_time', header: 'Hold time' },
  { accessorKey: 'snpa', header: 'SNPA' },
]
const ifColumns = [
  { accessorKey: 'name', header: 'Interface' },
  { accessorKey: 'state', header: 'State' },
  { accessorKey: 'type', header: 'Type' },
  { accessorKey: 'level', header: 'Level' },
]
const routeColumns = [
  { accessorKey: 'prefix', header: 'Prefix' },
  { accessorKey: 'level', header: 'Level' },
  { accessorKey: 'metric', header: 'Metric' },
  { id: 'next_hops', header: 'Next hop' },
]
</script>

<template>
  <div>
    <UAlert
      v-if="state?.error"
      class="mb-2"
      color="warning"
      variant="subtle"
      :title="`IS-IS: ${state.error}`"
    />
    <div v-if="loaded" class="mb-4 text-sm">
      <span class="text-muted">System id</span>
      <span v-if="state" class="ms-2 font-mono">{{ state.system_id }}</span>
      <span v-else class="ms-2 text-muted">not running</span>
    </div>

    <div class="mb-2 text-base font-semibold">Adjacencies</div>
    <div class="mb-4">
      <SearchInput v-model="nbr.search.value" class="mb-2" />
      <UTable :data="nbr.filtered.value" :columns="nbrColumns" :loading="loading">
        <template #system_id-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.system_id }}</span>
        </template>
        <template #state-cell="{ row }">
          <UBadge
            :color="stateColor(row.original.state)"
            variant="subtle"
            :label="row.original.state"
          />
        </template>
        <template #snpa-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.snpa }}</span>
        </template>
        <template #empty>
          <div class="py-4 text-center text-muted">No adjacencies.</div>
        </template>
      </UTable>
    </div>

    <div class="mt-6 mb-2 text-base font-semibold">Interfaces</div>
    <div class="mb-4">
      <SearchInput v-model="ifs.search.value" class="mb-2" />
      <UTable :data="ifs.filtered.value" :columns="ifColumns">
        <template #empty>
          <div class="py-4 text-center text-muted">No interfaces.</div>
        </template>
      </UTable>
    </div>

    <div class="mt-6 mb-2 text-base font-semibold">Routes</div>
    <div class="mb-4">
      <UAlert
        v-if="state?.routes_truncated"
        class="mb-2"
        color="neutral"
        variant="subtle"
        title="Only the first 2000 routes are shown. The console's vtysh shows them all."
      />
      <SearchInput v-model="route.search.value" class="mb-2" />
      <!-- Virtual scroll: the table can hold thousands of routes. -->
      <UTable
        :data="route.filtered.value"
        :columns="routeColumns"
        :virtualize="{ estimateSize: 29 }"
        sticky
        class="max-h-[70vh]"
      >
        <template #prefix-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.prefix }}</span>
        </template>
        <template #next_hops-cell="{ row }">
          <div v-for="(nh, i) in row.original.next_hops" :key="i" class="font-mono text-xs">
            {{ nh
            }}<span v-if="row.original.interfaces?.[i]" class="text-muted">
              via {{ row.original.interfaces[i] }}</span
            >
          </div>
        </template>
        <template #empty>
          <div class="py-4 text-center text-muted">No routes.</div>
        </template>
      </UTable>
    </div>
  </div>
</template>
