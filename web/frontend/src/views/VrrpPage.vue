<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- VRRP (FRR's vrrpd): the virtual routers of the virtual firewall
     (Virtual routers tab), and their state as FRR has it (VRRP info). -->
<script setup>
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { api, vrrpRouters } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useSearch, valuesText } from '@/utils/search'

const route = useRoute()
const router = useRouter()
const { store, ifaceNames, ifaceText } = useInstanceRefs()

const tabs = [
  { label: 'VRRP info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'Virtual routers', value: 'routers', slot: 'routers', icon: 'i-lucide-git-fork' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})

// ----- Info: loaded, and refreshed every 5 s, while its tab is open.
const status = ref(null)
const statusError = ref('')
const loading = ref(false)
async function loadStatus() {
  loading.value = true
  try {
    status.value = await api.agentVrrp()
    statusError.value = ''
  } catch (err) {
    statusError.value = errMsg(err)
  } finally {
    loading.value = false
  }
}
const auto = useAutoRefresh(loadStatus, { seconds: 5, active: () => tab.value === 'info' })

const mine = computed(() =>
  status.value?.instances?.find((i) => i.instance === store.current?.name),
)
// One row per virtual router and IP version.
const infoRows = computed(() =>
  (mine.value?.routers ?? []).flatMap((r) =>
    [
      ['IPv4', r.v4],
      ['IPv6', r.v6],
    ]
      .filter(([, f]) => f)
      .map(([family, f]) => ({ ...f, family, router: r })),
  ),
)
const info = useSearch(infoRows, (x) =>
  valuesText(
    ifaceText(x.router.interface),
    x.router.vrid,
    x.family,
    stateText(x),
    x.addresses,
    x.device,
    x.mac,
  ),
)
const stateText = (x) => (x.router.shutdown ? `${x.state} (shut down)` : x.state)
const stateColor = (s) => (s === 'Master' ? 'success' : s === 'Backup' ? 'neutral' : 'warning')
const infoColumns = [
  { id: 'interface', header: 'Interface' },
  { id: 'vrid', header: 'VRID' },
  { accessorKey: 'family', header: 'IP version' },
  { id: 'state', header: 'State' },
  { accessorKey: 'effective_priority', header: 'Priority' },
  { id: 'addresses', header: 'Addresses' },
  { id: 'device', header: 'Device / MAC' },
  { id: 'intervals', header: 'Master adv. / down (ms)' },
  { id: 'adverts', header: 'Adverts sent / received' },
  { accessorKey: 'transitions', header: 'Transitions' },
]

// ----- Virtual routers.
const ifaceItems = computed(() => ifaceNames.value.map((n) => ({ label: ifaceText(n), value: n })))
const versions = [
  { label: 'VRRPv3', value: 3 },
  { label: 'VRRPv2 (IPv4 only)', value: 2 },
]
const columns = [
  { key: 'interface', label: 'Interface', format: (r) => ifaceText(r.interface) },
  { key: 'vrid', label: 'VRID' },
  { key: 'ipv4', label: 'IPv4', class: 'font-mono', format: (r) => (r.ipv4 ?? []).join(', ') },
  { key: 'ipv6', label: 'IPv6', class: 'font-mono', format: (r) => (r.ipv6 ?? []).join(', ') },
  { key: 'priority', label: 'Priority' },
  { key: 'version', label: 'Version', format: (r) => `v${r.version}` },
  { key: 'preempt', label: 'Preempt' },
  { key: 'enabled', label: 'Enabled' },
  { key: 'description', label: 'Description' },
]
const fields = computed(() => [
  { key: 'interface', label: 'Interface', type: 'select', items: ifaceItems.value, required: true },
  {
    key: 'vrid',
    label: 'Virtual router id',
    type: 'number',
    required: true,
    placeholder: '1-255',
    hint: 'The same on every router of the group, and unique on the network: it sets the virtual MAC address (00:00:5e:00:01:id, IPv6 00:00:5e:00:02:id).',
  },
  {
    key: 'ipv4',
    label: 'IPv4 addresses',
    type: 'tags',
    placeholder: '192.168.1.254',
    hint: "In a network of the interface, and not the interface's own address: the clients' gateway.",
  },
  {
    key: 'ipv6',
    label: 'IPv6 addresses',
    type: 'tags',
    placeholder: 'fe80::1, 2001:db8:1::1',
    hint: 'A link-local address, or one in a network of the interface. The router advertisements still name the interface’s own link-local address.',
    show: (f) => f.version !== 2,
  },
  { key: 'version', label: 'Version', type: 'select', items: versions },
  {
    key: 'priority',
    label: 'Priority',
    type: 'number',
    placeholder: '100',
    hint: '1-254. The router with the highest priority is master; on a tie, the one with the highest interface address.',
  },
  {
    key: 'advertisement_interval',
    label: 'Advertisement interval (ms)',
    type: 'number',
    placeholder: '1000',
    hint: '10-40950, a multiple of 10 (VRRPv2: whole seconds). The same on every router of the group; a backup takes over after about three intervals without one.',
  },
  {
    key: 'preempt',
    label: 'Preempt',
    type: 'switch',
    hint: 'A router of higher priority takes over from the master. Off: the master stays master until it fails.',
  },
  {
    key: 'enabled',
    label: 'Enabled',
    type: 'switch',
    hint: 'Off: shut down; configured, but never master.',
  },
  { key: 'description', label: 'Description' },
])
const defaults = {
  version: 3,
  priority: 100,
  advertisement_interval: 1000,
  preempt: true,
  enabled: true,
  ipv4: [],
  ipv6: [],
}
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs">
      <template #routers>
        <CrudPage
          title="Virtual routers"
          description="VRRP virtual routers (FRR): addresses shared with other routers on the same network, held by the master and taken over by a backup when it fails. Rules and auto rules on an interface also match what is sent to its virtual routers."
          :api="vrrpRouters"
          :params="{ instance_id: store.currentId }"
          :columns="columns"
          :fields="fields"
          :defaults="defaults"
          noun="virtual router"
          new-label="New virtual router"
          :item-name="(r) => `virtual router ${r.vrid} on ${ifaceText(r.interface)}`"
        />
      </template>
      <template #info>
        <div class="card">
          <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <div class="text-lg font-semibold">VRRP info</div>
              <p class="max-w-3xl text-sm text-muted">
                The state of this virtual firewall's virtual routers as FRR has them: master or
                backup, per IP version.
              </p>
            </div>
            <AutoRefreshButton :auto="auto" :loading="loading" />
          </div>
          <UAlert
            v-if="statusError || mine?.error"
            class="mb-2"
            color="error"
            variant="subtle"
            :title="statusError || mine.error"
          />
          <SearchInput v-model="info.search.value" class="mb-2" />
          <UTable :data="info.filtered.value" :columns="infoColumns" :loading="loading && !status">
            <template #interface-cell="{ row }">{{
              ifaceText(row.original.router.interface)
            }}</template>
            <template #vrid-cell="{ row }">{{ row.original.router.vrid }}</template>
            <template #state-cell="{ row }">
              <UBadge
                :color="row.original.router.shutdown ? 'neutral' : stateColor(row.original.state)"
                variant="subtle"
                :label="stateText(row.original)"
              />
            </template>
            <template #addresses-cell="{ row }">
              <span class="font-mono text-xs">{{ row.original.addresses.join(', ') }}</span>
            </template>
            <template #device-cell="{ row }">
              <span class="font-mono text-xs">
                {{ [row.original.device, row.original.mac].filter(Boolean).join(' / ') }}
              </span>
            </template>
            <template #intervals-cell="{ row }">
              {{ row.original.master_adver_interval }} / {{ row.original.master_down_interval }}
            </template>
            <template #adverts-cell="{ row }">
              {{ row.original.advertisements_sent }} / {{ row.original.advertisements_received }}
            </template>
            <template #empty>
              <div class="py-4 text-center text-muted">
                {{ status ? 'No virtual routers deployed.' : '' }}
              </div>
            </template>
          </UTable>
        </div>
      </template>
    </UTabs>
  </NeedInstance>
</template>
