<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// OspfInfo: OSPFv2's and OSPFv3's state as FRR has it (agentapi.OSPFState):
// router ids, then neighbours, interfaces, areas and routes of both versions.
import { computed } from 'vue'
import SearchInput from '@/components/SearchInput.vue'
import { useSearch, valuesText } from '@/utils/search'

const props = defineProps({
  // OSPFState of each version, or null when that version is not running.
  v2: { type: Object, default: null },
  v3: { type: Object, default: null },
  // The answer came (a state null then means not running).
  loaded: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
})

const versions = computed(() => [
  { v: 2, name: 'OSPFv2', state: props.v2 },
  { v: 3, name: 'OSPFv3', state: props.v3 },
])
// The rows of both versions in one list, each with its version (v2, v3).
const rows = (k) =>
  computed(() =>
    versions.value.flatMap((x) => (x.state?.[k] ?? []).map((r) => ({ ...r, version: `v${x.v}` }))),
  )

const nbr = useSearch(rows('neighbors'), (n) =>
  valuesText(n.version, n.router_id, n.address, n.interface, n.state, n.role, n.uptime),
)
const ifs = useSearch(rows('interfaces'), (i) =>
  valuesText(i.version, i.name, i.area, i.address, i.state, i.network_type, i.passive && 'passive'),
)
const area = useSearch(rows('areas'), (a) => valuesText(a.version, a.id, a.type || 'normal'))
const route = useSearch(rows('routes'), (r) =>
  valuesText(r.version, r.prefix, r.type, r.area, r.next_hops, r.interfaces),
)
const truncated = computed(() => versions.value.filter((x) => x.state?.routes_truncated))

const stateColor = (s) =>
  s === 'Full' ? 'success' : s === '2-Way' ? 'neutral' : s ? 'warning' : 'neutral'

const areaColumns = [
  { accessorKey: 'version', header: 'Version' },
  { accessorKey: 'id', header: 'Area' },
  { id: 'type', header: 'Type' },
  { accessorKey: 'interfaces', header: 'Interfaces' },
  { accessorKey: 'full_adjacencies', header: 'Full adjacencies' },
  { accessorKey: 'lsas', header: 'LSAs' },
]
const ifColumns = [
  { accessorKey: 'version', header: 'Version' },
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
  { accessorKey: 'version', header: 'Version' },
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
  { accessorKey: 'version', header: 'Version' },
  { accessorKey: 'prefix', header: 'Prefix' },
  { accessorKey: 'type', header: 'Type' },
  { accessorKey: 'area', header: 'Area' },
  { accessorKey: 'cost', header: 'Cost' },
  { id: 'next_hops', header: 'Next hop' },
]
</script>

<template>
  <div>
    <template v-for="x in versions" :key="x.v">
      <UAlert
        v-if="x.state?.error"
        class="mb-2"
        color="warning"
        variant="subtle"
        :title="`${x.name}: ${x.state.error}`"
      />
    </template>
    <div v-if="loaded" class="mb-4 flex flex-wrap gap-x-6 gap-y-1 text-sm">
      <span v-for="x in versions" :key="x.v">
        <span class="text-muted">{{ x.name }} router id</span>
        <span v-if="x.state" class="ms-2 font-mono">{{ x.state.router_id }}</span>
        <span v-else class="ms-2 text-muted">not running</span>
      </span>
    </div>

    <div class="mb-2 text-base font-semibold">Neighbours</div>
    <div class="mb-4">
      <SearchInput v-model="nbr.search.value" class="mb-2" />
      <UTable :data="nbr.filtered.value" :columns="nbrColumns" :loading="loading">
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
    </div>

    <div class="mt-6 mb-2 text-base font-semibold">Interfaces</div>
    <div class="mb-4">
      <SearchInput v-model="ifs.search.value" class="mb-2" />
      <UTable :data="ifs.filtered.value" :columns="ifColumns">
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
    </div>

    <div class="mt-6 mb-2 text-base font-semibold">Areas</div>
    <div class="mb-4">
      <SearchInput v-model="area.search.value" class="mb-2" />
      <UTable :data="area.filtered.value" :columns="areaColumns">
        <template #id-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.id }}</span>
        </template>
        <template #type-cell="{ row }">{{ row.original.type || 'normal' }}</template>
        <template #empty>
          <div class="py-4 text-center text-muted">No areas.</div>
        </template>
      </UTable>
    </div>

    <div class="mt-6 mb-2 text-base font-semibold">Routes</div>
    <div class="mb-4">
      <UAlert
        v-for="x in truncated"
        :key="x.v"
        class="mb-2"
        color="neutral"
        variant="subtle"
        :title="`Only the first 2000 ${x.name} routes are shown. The console's vtysh shows them all.`"
      />
      <SearchInput v-model="route.search.value" class="mb-2" />
      <UTable :data="route.filtered.value" :columns="routeColumns">
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
