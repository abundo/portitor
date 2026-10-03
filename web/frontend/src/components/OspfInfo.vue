<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// OspfInfo: one OSPF version's state as FRR has it (agentapi.OSPFState):
// router id, areas, interfaces, neighbours and routes.
import { computed } from 'vue'
import SearchInput from '@/components/SearchInput.vue'
import { useSearch, valuesText } from '@/utils/search'

const props = defineProps({
  // OSPFState, or null when the version is not running.
  state: { type: Object, default: null },
  version: { type: Number, required: true },
  // The answer came (state null then means not running).
  loaded: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
})

const name = computed(() => (props.version === 3 ? 'OSPFv3' : 'OSPFv2'))
const areas = computed(() => props.state?.areas ?? [])
const interfaces = computed(() => props.state?.interfaces ?? [])
const neighbors = computed(() => props.state?.neighbors ?? [])
const routes = computed(() => props.state?.routes ?? [])

const ifSearch = useSearch(interfaces, (i) =>
  valuesText(i.name, i.area, i.address, i.state, i.network_type, i.passive && 'passive'),
)
const nbrSearch = useSearch(neighbors, (n) =>
  valuesText(n.router_id, n.address, n.interface, n.state, n.role, n.uptime),
)
const routeSearch = useSearch(routes, (r) =>
  valuesText(r.prefix, r.type, r.area, r.next_hops, r.interfaces),
)
const areaSearch = useSearch(areas, (a) => valuesText(a.id, a.type || 'normal'))

const stateColor = (s) =>
  s === 'Full' ? 'success' : s === '2-Way' ? 'neutral' : s ? 'warning' : 'neutral'

const areaColumns = [
  { accessorKey: 'id', header: 'Area' },
  { id: 'type', header: 'Type' },
  { accessorKey: 'interfaces', header: 'Interfaces' },
  { accessorKey: 'full_adjacencies', header: 'Full adjacencies' },
  { accessorKey: 'lsas', header: 'LSAs' },
]
const ifColumns = [
  { accessorKey: 'name', header: 'Interface' },
  { accessorKey: 'area', header: 'Area' },
  { accessorKey: 'address', header: 'Address' },
  { accessorKey: 'state', header: 'State' },
  { accessorKey: 'network_type', header: 'Network' },
  { accessorKey: 'cost', header: 'Cost' },
  { accessorKey: 'priority', header: 'Priority' },
  { id: 'nbrs', header: 'Neighbours / adjacent' },
  { id: 'dr', header: 'DR / BDR' },
]
const nbrColumns = [
  { accessorKey: 'router_id', header: 'Neighbour' },
  { accessorKey: 'address', header: 'Address' },
  { accessorKey: 'interface', header: 'Interface' },
  { accessorKey: 'state', header: 'State' },
  { accessorKey: 'role', header: 'Role' },
  { accessorKey: 'priority', header: 'Priority' },
  { accessorKey: 'uptime', header: 'Up' },
  { accessorKey: 'dead_time', header: 'Dead time' },
]
const routeColumns = [
  { accessorKey: 'prefix', header: 'Prefix' },
  { accessorKey: 'type', header: 'Type' },
  { accessorKey: 'area', header: 'Area' },
  { accessorKey: 'cost', header: 'Cost' },
  { id: 'next_hops', header: 'Next hop' },
]
</script>

<template>
  <div>
    <UAlert
      v-if="loaded && !state"
      class="mb-2"
      color="neutral"
      variant="subtle"
      :title="`${name} is not running in this virtual firewall.`"
      :description="`Turn it on under ${name} config, then commit.`"
    />
    <template v-if="state">
      <UAlert
        v-if="state.error"
        class="mb-2"
        color="warning"
        variant="subtle"
        :title="state.error"
      />
      <dl class="mb-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt class="text-muted">Router id</dt>
        <dd class="font-mono">{{ state.router_id }}</dd>
      </dl>

      <div class="mb-2 font-semibold">Neighbours</div>
      <SearchInput v-model="nbrSearch.search.value" class="mb-2" />
      <UTable :data="nbrSearch.filtered.value" :columns="nbrColumns" :loading="loading">
        <template #router_id-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.router_id }}</span>
        </template>
        <template #address-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.address }}</span>
        </template>
        <template #state-cell="{ row }">
          <UBadge
            :color="stateColor(row.original.state)"
            variant="subtle"
            :label="row.original.state"
          />
        </template>
        <template #empty>
          <div class="py-4 text-center text-muted">No neighbours.</div>
        </template>
      </UTable>

      <div class="mt-6 mb-2 font-semibold">Interfaces</div>
      <SearchInput v-model="ifSearch.search.value" class="mb-2" />
      <UTable :data="ifSearch.filtered.value" :columns="ifColumns">
        <template #name-cell="{ row }">
          {{ row.original.name }}
          <UBadge
            v-if="row.original.passive"
            class="ms-1"
            color="neutral"
            variant="subtle"
            size="sm"
            label="passive"
          />
        </template>
        <template #address-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.address }}</span>
        </template>
        <template #nbrs-cell="{ row }">
          {{ row.original.neighbors }} / {{ row.original.adjacent }}
        </template>
        <template #dr-cell="{ row }">
          <span class="font-mono text-xs">
            {{ [row.original.dr, row.original.bdr].filter(Boolean).join(' / ') }}
          </span>
        </template>
        <template #empty>
          <div class="py-4 text-center text-muted">No interfaces.</div>
        </template>
      </UTable>

      <div class="mt-6 mb-2 font-semibold">Areas</div>
      <SearchInput v-model="areaSearch.search.value" class="mb-2" />
      <UTable :data="areaSearch.filtered.value" :columns="areaColumns">
        <template #id-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.id }}</span>
        </template>
        <template #type-cell="{ row }">{{ row.original.type || 'normal' }}</template>
        <template #empty>
          <div class="py-4 text-center text-muted">No areas.</div>
        </template>
      </UTable>

      <div class="mt-6 mb-2 font-semibold">Routes</div>
      <UAlert
        v-if="state.routes_truncated"
        class="mb-2"
        color="neutral"
        variant="subtle"
        title="Only the first 2000 routes are shown. The console's vtysh shows them all."
      />
      <SearchInput v-model="routeSearch.search.value" class="mb-2" />
      <UTable :data="routeSearch.filtered.value" :columns="routeColumns">
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
    </template>
  </div>
</template>
