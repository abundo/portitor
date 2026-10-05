<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- Routing: the virtual firewall's IPv4 and IPv6 routes in all its routing
     tables as the kernel has them, with who added each (protocol). -->
<script setup>
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { computed, ref } from 'vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useSearch, valuesText } from '@/utils/search'

const { store, ifaceText } = useInstanceRefs()

// Loaded, and refreshed every 10 s, while the page is open.
const table = ref(null)
const error = ref('')
const loading = ref(false)
async function load() {
  loading.value = true
  try {
    table.value = await api.agentRoutingTable()
    error.value = ''
  } catch (err) {
    error.value = errMsg(err)
  } finally {
    loading.value = false
  }
}
const auto = useAutoRefresh(load, { seconds: 10 })

// rt_protos names, and the agent's own number.
const protocolLabel = {
  99: 'portitor',
  ra: 'RA',
  dhcp: 'DHCP',
  bgp: 'BGP',
  ospf: 'OSPF',
  static: 'static (FRR)',
  kernel: 'connected',
  zebra: 'FRR',
}
const protoText = (p) => protocolLabel[p] ?? p
const familyLabel = { ipv4: 'IPv4', ipv6: 'IPv6' }
// main first, then local, then the others by name.
const tableRank = (t) => (t === 'main' ? 0 : t === 'local' ? 2 : 1)
const rows = computed(() =>
  (table.value?.routes ?? [])
    .filter((r) => r.instance === store.current?.name)
    .sort(
      (a, b) =>
        a.family.localeCompare(b.family) ||
        tableRank(a.table) - tableRank(b.table) ||
        a.table.localeCompare(b.table, undefined, { numeric: true }),
    ),
)
const typeText = (r) => [r.type !== 'unicast' && r.type, r.scope].filter(Boolean).join(', ')
const { search, filtered } = useSearch(rows, (r) =>
  valuesText(
    familyLabel[r.family],
    r.table,
    r.destination,
    r.gateway,
    r.peer_instance && `VF ${r.peer_instance}`,
    r.interface && ifaceText(r.interface),
    protoText(r.protocol),
    typeText(r),
    r.source,
    r.metric,
  ),
)
const columns = [
  { id: 'family', header: 'Family' },
  { accessorKey: 'table', header: 'Table' },
  { accessorKey: 'destination', header: 'Destination' },
  { accessorKey: 'gateway', header: 'Gateway' },
  { id: 'interface', header: 'Interface' },
  { id: 'protocol', header: 'Protocol' },
  { accessorKey: 'metric', header: 'Metric' },
  { accessorKey: 'source', header: 'Source' },
  { id: 'type', header: 'Type / scope' },
]
</script>

<template>
  <NeedInstance>
    <div class="card">
      <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div class="text-lg font-semibold">Routing</div>
          <p class="max-w-3xl text-sm text-muted">
            The IPv4 and IPv6 routes of this virtual firewall in all its routing tables (main, local
            and any other) as the kernel has them. Protocol is who added the route: connected
            networks, DHCP and RA, the static routes deployed (portitor), and FRR's BGP, OSPF and
            static (with BFD) routes.
          </p>
        </div>
        <AutoRefreshButton :auto="auto" :loading="loading" />
      </div>
      <UAlert v-if="error" class="mb-2" color="error" variant="subtle" :title="error" />
      <div class="mb-2 flex items-center gap-3">
        <SearchInput v-model="search" />
        <span class="text-sm text-muted">{{ filtered.length }} of {{ rows.length }} routes</span>
      </div>
      <UTable
        :data="filtered"
        :columns="columns"
        :loading="loading && !table"
        :virtualize="{ estimateSize: 29 }"
        sticky
        class="max-h-[70vh]"
      >
        <template #family-cell="{ row }">{{ familyLabel[row.original.family] }}</template>
        <template #destination-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.destination }}</span>
        </template>
        <template #gateway-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.gateway }}</span>
          <UBadge
            v-if="row.original.peer_instance"
            class="ms-1"
            color="neutral"
            variant="subtle"
            size="sm"
            :label="`VF ${row.original.peer_instance}`"
          />
        </template>
        <template #source-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.source }}</span>
        </template>
        <template #interface-cell="{ row }">
          {{ row.original.interface ? ifaceText(row.original.interface) : '' }}
        </template>
        <template #protocol-cell="{ row }">{{ protoText(row.original.protocol) }}</template>
        <template #type-cell="{ row }">{{ typeText(row.original) }}</template>
        <template #empty>
          <div class="py-4 text-center text-muted">No routes.</div>
        </template>
      </UTable>
    </div>
  </NeedInstance>
</template>
