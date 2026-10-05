<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- BFD (FRR's bfdd): the interfaces of the virtual firewall with BFD and
     their timers (Interfaces tab), and the sessions as FRR has them (BFD
     info). Static routes, OSPF interfaces and BGP neighbours turn BFD on
     for themselves; it runs on the interfaces listed here. -->
<script setup>
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { api, bfdInterfaces, bgpNeighbors, bgpPeerGroups, ospfInterfaces, routes } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useSearch, valuesText } from '@/utils/search'

const route = useRoute()
const router = useRouter()
const { store, ifaceNames, ifaceText } = useInstanceRefs()

const tabs = [
  { label: 'BFD info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'Interfaces', value: 'interfaces', slot: 'interfaces', icon: 'i-lucide-heart-pulse' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})

// ----- Info: loaded, and refreshed every 5 s, while its tab is open.
const status = ref(null)
const statusError = ref('')
const loading = ref(false)
// What asks for BFD: static routes, BGP neighbours (or their peer group) and
// OSPF interfaces with it on, loaded with the sessions.
const users = ref({ routes: [], neighbors: [], groups: [], ospf: [] })
async function loadUsers() {
  const params = { instance_id: store.currentId }
  const [r, n, g, o] = await Promise.all([
    routes.list(params),
    bgpNeighbors.list(params),
    bgpPeerGroups.list(params),
    ospfInterfaces.list(params),
  ])
  users.value = { routes: r, neighbors: n, groups: g, ospf: o }
}
async function loadStatus() {
  loading.value = true
  try {
    ;[status.value] = await Promise.all([api.agentBfd(), loadUsers()])
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
const peers = computed(() => mine.value?.peers ?? [])
// usedBy lists the protocols a session serves: a static route by its
// gateway, a BGP neighbour by its address, OSPF by the session's interface
// (OSPFv2 for an IPv4 peer, OSPFv3 for IPv6).
const sameAddr = (a, b) => !!a && !!b && a.toLowerCase() === b.toLowerCase()
function usedBy(p) {
  const u = users.value
  const out = []
  if (u.routes.some((r) => r.enabled && r.bfd && sameAddr(r.gateway, p.peer))) out.push('Static')
  const groupBfd = new Set(u.groups.filter((g) => g.bfd).map((g) => g.name))
  if (
    u.neighbors.some(
      (n) => n.enabled && (n.bfd || groupBfd.has(n.peer_group)) && sameAddr(n.address, p.peer),
    )
  )
    out.push('BGP')
  const version = p.peer?.includes(':') ? 3 : 2
  if (u.ospf.some((o) => o.bfd && o.version === version && o.name === p.interface))
    out.push(version === 3 ? 'OSPFv3' : 'OSPF')
  return out
}
const info = useSearch(peers, (p) =>
  valuesText(
    ifaceText(p.interface),
    p.peer,
    p.local,
    p.status,
    p.diagnostic,
    p.profile,
    ...usedBy(p),
  ),
)
const statusColor = (s) => (s === 'up' ? 'success' : s === 'down' ? 'error' : 'warning')
function duration(s) {
  if (!s) return ''
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  return [d && `${d}d`, (d || h) && `${h}h`, (d || h || m) && `${m}m`, `${s % 60}s`]
    .filter(Boolean)
    .join(' ')
}
const infoColumns = [
  { id: 'interface', header: 'Interface' },
  { accessorKey: 'peer', header: 'Peer' },
  { accessorKey: 'local', header: 'Local address' },
  { id: 'status', header: 'Status' },
  { id: 'used_by', header: 'Used by' },
  { id: 'time', header: 'Up / down for' },
  { id: 'local_timers', header: 'Rx / tx (ms) × multiplier' },
  { id: 'remote_timers', header: 'Peer rx / tx (ms) × multiplier' },
  { accessorKey: 'diagnostic', header: 'Diagnostic' },
]

// ----- Interfaces.
const ifaceItems = computed(() => ifaceNames.value.map((n) => ({ label: ifaceText(n), value: n })))
const columns = [
  { key: 'interface', label: 'Interface', format: (r) => ifaceText(r.interface) },
  { key: 'enabled', label: 'Enabled' },
  { key: 'receive_interval', label: 'Receive (ms)' },
  { key: 'transmit_interval', label: 'Transmit (ms)' },
  { key: 'detect_multiplier', label: 'Multiplier' },
  { key: 'passive', label: 'Passive' },
  { key: 'description', label: 'Description' },
]
const fields = computed(() => [
  { key: 'interface', label: 'Interface', type: 'select', items: ifaceItems.value, required: true },
  {
    key: 'enabled',
    label: 'Enabled',
    type: 'switch',
    hint: 'Off: no BFD on the interface; the static routes, OSPF and BGP neighbours that ask for BFD run without it there.',
  },
  {
    key: 'receive_interval',
    label: 'Receive interval (ms)',
    type: 'number',
    placeholder: '300',
    hint: '10-60000: how often the peer may send.',
  },
  {
    key: 'transmit_interval',
    label: 'Transmit interval (ms)',
    type: 'number',
    placeholder: '300',
    hint: '10-60000: how often this firewall sends, at the most. The slower of this and the peer’s receive interval is used.',
  },
  {
    key: 'detect_multiplier',
    label: 'Detect multiplier',
    type: 'number',
    placeholder: '3',
    hint: '2-255: how many packets may be lost before the peer is down. 300 ms × 3: the peer is down after 0.9 s.',
  },
  {
    key: 'passive',
    label: 'Passive',
    type: 'switch',
    hint: 'Waits for the peer to start the session.',
  },
  { key: 'description', label: 'Description' },
])
const defaults = {
  enabled: true,
  receive_interval: 300,
  transmit_interval: 300,
  detect_multiplier: 3,
  passive: false,
}
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs">
      <template #interfaces>
        <CrudPage
          title="BFD interfaces"
          description="BFD (FRR) on the interfaces of this virtual firewall: fast detection of a lost neighbour. Static routes (their gateway), OSPF interfaces and BGP neighbours turn BFD on in their own settings, and use it on the interfaces listed and enabled here, with these timers."
          :api="bfdInterfaces"
          :params="{ instance_id: store.currentId }"
          :columns="columns"
          :fields="fields"
          :defaults="defaults"
          noun="BFD interface"
          new-label="New BFD interface"
          :item-name="(r) => `BFD on ${ifaceText(r.interface)}`"
        />
      </template>
      <template #info>
        <div class="card">
          <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <div class="text-lg font-semibold">BFD info</div>
              <p class="max-w-3xl text-sm text-muted">
                The BFD sessions of this virtual firewall as FRR has them: one per neighbour or
                gateway that uses BFD, with the protocols (static routes, BGP, OSPF) that use it.
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
            <template #interface-cell="{ row }">{{ ifaceText(row.original.interface) }}</template>
            <template #peer-cell="{ row }">
              <span class="font-mono text-xs">{{ row.original.peer }}</span>
            </template>
            <template #local-cell="{ row }">
              <span class="font-mono text-xs">{{ row.original.local }}</span>
            </template>
            <template #status-cell="{ row }">
              <UBadge
                :color="statusColor(row.original.status)"
                variant="subtle"
                :label="row.original.status"
              />
            </template>
            <template #used_by-cell="{ row }">
              <div class="flex flex-wrap gap-1">
                <UBadge
                  v-for="u in usedBy(row.original)"
                  :key="u"
                  color="neutral"
                  variant="outline"
                  :label="u"
                />
              </div>
            </template>
            <template #time-cell="{ row }">
              {{
                duration(row.original.status === 'up' ? row.original.uptime : row.original.downtime)
              }}
            </template>
            <template #local_timers-cell="{ row }">
              {{ row.original.receive_interval }} / {{ row.original.transmit_interval }} ×
              {{ row.original.detect_multiplier }}
            </template>
            <template #remote_timers-cell="{ row }">
              {{ row.original.remote_receive_interval }} /
              {{ row.original.remote_transmit_interval }} ×
              {{ row.original.remote_detect_multiplier }}
            </template>
            <template #empty>
              <div class="py-4 text-center text-muted">
                {{ status ? 'No BFD sessions.' : '' }}
              </div>
            </template>
          </UTable>
        </div>
      </template>
    </UTabs>
  </NeedInstance>
</template>
