<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- Routing: the static routes (Routes tab), and the virtual firewall's
     IPv4 and IPv6 routing tables as the kernel has them (Routing info). -->
<script setup>
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { api, routes } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useSearch, valuesText } from '@/utils/search'

const route = useRoute()
const router = useRouter()
const { store, ifaceItems, ifaceName, ifaceText } = useInstanceRefs()

const tabs = [
  { label: 'Routes', value: 'routes', slot: 'routes', icon: 'i-lucide-route' },
  { label: 'Routing info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
]
// The tab is in the URL (?tab=info), so links can open one.
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'routes'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'routes' ? undefined : v } }),
})

// Routing info: loaded, and refreshed every 10 s, while its tab is open.
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
let timer = null
watch(
  tab,
  (t) => {
    clearInterval(timer)
    timer = null
    if (t === 'info') {
      load()
      timer = setInterval(load, 10000)
    }
  },
  { immediate: true },
)
onBeforeUnmount(() => clearInterval(timer))

const protocolLabel = { 99: 'portitor', ra: 'RA', dhcp: 'DHCP' }
const familyRows = (fam) =>
  computed(() =>
    (table.value?.routes ?? []).filter(
      (r) => r.instance === store.current?.name && r.family === fam,
    ),
  )
const routeText = (r) =>
  valuesText(
    r.destination,
    r.gateway,
    r.interface && ifaceText(r.interface),
    protocolLabel[r.protocol] ?? r.protocol,
    r.type,
    r.scope,
    r.source,
    r.metric,
  )
const v4 = useSearch(familyRows('ipv4'), routeText)
const v6 = useSearch(familyRows('ipv6'), routeText)
const families = [
  { title: 'IPv4', s: v4 },
  { title: 'IPv6', s: v6 },
]
const infoColumns = [
  { accessorKey: 'destination', header: 'Destination' },
  { accessorKey: 'gateway', header: 'Gateway' },
  { id: 'interface', header: 'Interface' },
  { id: 'protocol', header: 'Protocol' },
  { accessorKey: 'metric', header: 'Metric' },
  { accessorKey: 'source', header: 'Source' },
  { id: 'type', header: 'Type / scope' },
]

const columns = [
  { key: 'destination', label: 'Destination', class: 'font-mono' },
  { key: 'gateway', label: 'Gateway', class: 'font-mono' },
  { key: 'interface_id', label: 'Interface', format: (r) => ifaceName(r.interface_id) },
  { key: 'metric', label: 'Metric' },
  { key: 'enabled', label: 'Enabled' },
  { key: 'description', label: 'Description' },
]
const fields = [
  {
    key: 'destination',
    label: 'Destination',
    type: 'addr',
    required: true,
    placeholder: '10.50.0.0/16, default or a name',
  },
  {
    key: 'gateway',
    label: 'Gateway',
    type: 'addr',
    placeholder: '192.168.1.254 or a host',
    hint: 'With named IPv4 + IPv6 destinations/gateways, one route is made per IP version.',
  },
  {
    key: 'interface_id',
    label: 'Interface',
    type: 'select',
    items: () => ifaceItems.value,
    nullable: true,
  },
  {
    key: 'metric',
    label: 'Metric',
    type: 'number',
    hint: 'DHCP default routes use metric 100, so a static default with a lower metric wins.',
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
]
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs">
      <template #routes>
        <CrudPage
          title="Routes"
          description="Static routes of this virtual firewall. Connected networks and DHCP default routes are added automatically."
          :api="routes"
          :params="{ instance_id: store.currentId }"
          :columns="columns"
          :fields="fields"
          :defaults="{ enabled: true, metric: 0 }"
          new-label="New route"
          :item-name="(r) => `route ${r.destination}`"
        />
      </template>
      <template #info>
        <div class="card">
          <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <div class="text-lg font-semibold">Routing info</div>
              <p class="max-w-3xl text-sm text-muted">
                The IPv4 and IPv6 routing tables of this virtual firewall as the kernel has them:
                connected networks, DHCP and RA routes, and the static routes deployed (protocol
                portitor).
              </p>
            </div>
            <UButton
              icon="i-lucide-refresh-cw"
              color="neutral"
              variant="outline"
              label="Refresh"
              :loading="loading"
              @click="load"
            />
          </div>
          <UAlert v-if="error" class="mb-2" color="error" variant="subtle" :title="error" />
          <div v-for="f in families" :key="f.title" class="mb-6">
            <div class="mb-2 font-semibold">{{ f.title }}</div>
            <SearchInput v-model="f.s.search.value" class="mb-2" />
            <UTable :data="f.s.filtered.value" :columns="infoColumns" :loading="loading && !table">
              <template #destination-cell="{ row }">
                <span class="font-mono text-xs">{{ row.original.destination }}</span>
              </template>
              <template #gateway-cell="{ row }">
                <span class="font-mono text-xs">{{ row.original.gateway }}</span>
              </template>
              <template #source-cell="{ row }">
                <span class="font-mono text-xs">{{ row.original.source }}</span>
              </template>
              <template #interface-cell="{ row }">
                {{ row.original.interface ? ifaceText(row.original.interface) : '' }}
              </template>
              <template #protocol-cell="{ row }">
                {{ protocolLabel[row.original.protocol] ?? row.original.protocol }}
              </template>
              <template #type-cell="{ row }">
                {{
                  [row.original.type !== 'unicast' && row.original.type, row.original.scope]
                    .filter(Boolean)
                    .join(', ')
                }}
              </template>
              <template #empty>
                <div class="py-4 text-center text-muted">No routes.</div>
              </template>
            </UTable>
          </div>
        </div>
      </template>
    </UTabs>
  </NeedInstance>
</template>
