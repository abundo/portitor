<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- Neighbours. Info: what the virtual firewall's interfaces see next to
     them, by interface: the LLDP neighbours heard (an info button shows all
     their frame said), then the ARP (IPv4) and ND (IPv6) entries; of all VRFs
     or one, chosen at the top. Static entries: permanent ARP and ND entries. -->
<script setup>
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import CrudPage from '@/components/CrudPage.vue'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import VrfSelect from '@/components/VrfSelect.vue'
import { api, staticNeighbours } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useVrfChoice } from '@/composables/useVrfChoice'
import { useSearch, valuesText } from '@/utils/search'
import { ago, when } from '@/utils/time'

const route = useRoute()
const router = useRouter()
const tabs = [
  { label: 'Info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'Static entries', value: 'static', slot: 'static', icon: 'i-lucide-pin' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})

const { store, ifaceList, ifaceNames, ifaceText, ifaceItems, ifaceName } = useInstanceRefs()
const { vrf, vrfList, vrfItems, showsName } = useVrfChoice({ all: true })
const ifaceVrf = (name) => ifaceList.value.find((i) => i.name === name)?.vrf || ''
const data = ref(null)
const error = ref('')
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    data.value = await api.agentNeighbours()
    error.value = ''
  } catch (err) {
    error.value = errMsg(err)
  } finally {
    loading.value = false
  }
}
const auto = useAutoRefresh(load, { seconds: 10, active: () => tab.value === 'info' })

const mine = (x) => x.instance === store.current?.name
const lldpPorts = computed(() => (data.value?.lldp_ports ?? []).filter(mine))
const portErrors = computed(() => lldpPorts.value.filter((p) => p.error))

// One row per neighbour: { kind: 'lldp' | 'arp' | 'nd', interface,
// neighbour, mac, details, n (what the agent sent) }.
const protoOrder = { lldp: 0, arp: 1, nd: 2 }
const rows = computed(() => {
  const out = []
  for (const n of (data.value?.lldp ?? []).filter(mine)) {
    out.push({
      kind: 'lldp',
      interface: n.interface,
      vrf: ifaceVrf(n.interface),
      neighbour: n.system_name || n.chassis_id,
      address: n.management_addresses?.join(', ') ?? '',
      mac: n.source_mac,
      details: [n.port_id, n.port_description].filter(Boolean).join(' — '),
      n,
    })
  }
  for (const n of (data.value?.ip ?? []).filter(mine)) {
    out.push({
      kind: n.family === 'ipv6' ? 'nd' : 'arp',
      interface: n.interface,
      vrf: n.vrf ?? '',
      neighbour: '',
      address: n.address,
      mac: n.mac ?? '',
      details: [n.state, n.router && 'router'].filter(Boolean).join(', '),
      n,
    })
  }
  // By interface in the instance's order, then LLDP, ARP, ND, then address.
  const pos = new Map(ifaceNames.value.map((name, i) => [name, i]))
  const at = (r) => pos.get(r.interface) ?? Infinity
  return out
    .filter((r) => showsName(r.vrf))
    .sort(
      (a, b) =>
        at(a) - at(b) ||
        a.interface.localeCompare(b.interface) ||
        protoOrder[a.kind] - protoOrder[b.kind] ||
        (a.neighbour + a.address).localeCompare(b.neighbour + b.address, undefined, {
          numeric: true,
        }),
    )
})
const protoLabel = { lldp: 'LLDP', arp: 'ARP', nd: 'ND' }
const { search, filtered } = useSearch(rows, (r) =>
  valuesText(
    ifaceText(r.interface),
    r.vrf,
    protoLabel[r.kind],
    r.neighbour,
    r.address,
    r.mac,
    r.details,
  ),
)

const columns = computed(() => [
  { id: 'info', header: '' },
  { id: 'interface', header: 'Interface' },
  ...(vrfList.value.length ? [{ accessorKey: 'vrf', header: 'VRF' }] : []),
  { id: 'kind', header: 'Protocol' },
  { accessorKey: 'neighbour', header: 'Name' },
  { accessorKey: 'address', header: 'Address' },
  { accessorKey: 'mac', header: 'MAC' },
  { accessorKey: 'details', header: 'Port / state' },
])

// The rows of an LLDP neighbour's details.
function lldpRows(n) {
  const r = [
    ['System name', n.system_name],
    ['System description', n.system_description],
    ['Chassis ID', n.chassis_id && `${n.chassis_id} (${n.chassis_id_subtype})`],
    ['Port ID', n.port_id && `${n.port_id} (${n.port_id_subtype})`],
    ['Port description', n.port_description],
    ['Port VLAN', n.port_vlan || ''],
    ['VLANs', n.vlan_names?.join(', ')],
    ['Management addresses', n.management_addresses?.join(', ')],
    ['Capabilities', n.capabilities?.join(', ')],
    ['Enabled capabilities', n.enabled_capabilities?.join(', ')],
    ['Maximum frame size', n.max_frame || ''],
    ['Source MAC', n.source_mac],
    ['TTL', `${n.ttl} s`],
    ['First seen', `${when(n.first_seen)} (${ago(n.first_seen)})`],
    ['Last seen', `${when(n.last_seen)} (${ago(n.last_seen)})`],
  ]
  return r.filter(([, v]) => v !== '' && v != null)
}

// ----- Static entries: permanent ARP (IPv4) and ND (IPv6) entries.
const isV6 = (a) => (a ?? '').includes(':')
const staticColumns = [
  { key: 'interface_id', label: 'Interface', format: (r) => ifaceName(r.interface_id) },
  { key: 'kind', label: 'Protocol', format: (r) => (isV6(r.address) ? 'ND' : 'ARP') },
  { key: 'address', label: 'Address', class: 'font-mono' },
  { key: 'mac', label: 'MAC', class: 'font-mono' },
  { key: 'enabled', label: 'Enabled' },
  { key: 'description', label: 'Description' },
]
const staticFields = [
  {
    key: 'interface_id',
    label: 'Interface',
    type: 'select',
    items: () => ifaceItems.value,
    required: true,
  },
  {
    key: 'address',
    label: 'Address',
    required: true,
    placeholder: '192.168.1.10 or fd00::10',
    hint: 'An IPv4 address makes a static ARP entry, an IPv6 address a static ND entry.',
  },
  { key: 'mac', label: 'MAC', required: true, placeholder: '02:00:5e:00:01:01' },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
]
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
      <template #info>
        <div class="card">
          <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <div class="text-lg font-semibold">Neighbours</div>
              <p class="max-w-3xl text-sm text-muted">
                What this virtual firewall's interfaces see next to them: LLDP neighbours, on the
                interfaces with LLDP turned on under
                <RouterLink to="/interfaces" class="text-primary">Interfaces</RouterLink>, and the
                ARP (IPv4) and ND (IPv6) tables.
              </p>
            </div>
            <AutoRefreshButton :auto="auto" :loading="loading" />
          </div>

          <div class="mb-2 space-y-2">
            <UAlert v-if="error" color="error" variant="subtle" :title="error" />
            <UAlert
              v-for="p in portErrors"
              :key="p.interface"
              color="warning"
              variant="subtle"
              :title="`LLDP on ${ifaceText(p.interface)}: ${p.error}`"
            />
          </div>
          <div>
            <div class="mb-2 flex items-center gap-3">
              <VrfSelect v-model="vrf" :items="vrfItems" />
              <SearchInput v-model="search" />
              <span v-if="lldpPorts.length" class="text-sm text-muted">
                LLDP on {{ lldpPorts.map((p) => ifaceText(p.interface)).join(', ') }}
              </span>
            </div>
            <UTable :data="filtered" :columns="columns" :loading="loading && !data">
              <template #info-cell="{ row }">
                <UPopover
                  v-if="row.original.kind === 'lldp'"
                  :content="{ side: 'bottom', align: 'start' }"
                >
                  <UButton
                    size="xs"
                    color="neutral"
                    variant="ghost"
                    icon="i-lucide-info"
                    aria-label="LLDP neighbour details"
                    title="LLDP neighbour details"
                  />
                  <template #content>
                    <div class="max-w-lg p-3 text-sm">
                      <div class="mb-2 font-semibold">
                        LLDP neighbour on {{ ifaceText(row.original.interface) }}
                      </div>
                      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5">
                        <template v-for="[k, v] in lldpRows(row.original.n)" :key="k">
                          <dt class="text-muted">{{ k }}</dt>
                          <dd class="font-mono text-xs break-all whitespace-pre-wrap">{{ v }}</dd>
                        </template>
                      </dl>
                    </div>
                  </template>
                </UPopover>
              </template>
              <template #interface-cell="{ row }">{{ ifaceText(row.original.interface) }}</template>
              <template #kind-cell="{ row }">
                <UBadge
                  :color="row.original.kind === 'lldp' ? 'primary' : 'neutral'"
                  variant="subtle"
                  size="sm"
                  :label="protoLabel[row.original.kind]"
                />
              </template>
              <template #address-cell="{ row }">
                <span class="font-mono text-xs">{{ row.original.address }}</span>
              </template>
              <template #mac-cell="{ row }">
                <span class="font-mono text-xs">{{ row.original.mac }}</span>
              </template>
              <template #empty>
                <div class="py-4 text-center text-muted">
                  {{ rows.length ? 'No neighbour matches.' : 'No neighbours seen.' }}
                </div>
              </template>
            </UTable>
          </div>
        </div>
      </template>
      <template #static>
        <CrudPage
          title="Static entries"
          noun="static entry"
          description="Permanent ARP (IPv4) and ND (IPv6) entries of this virtual firewall's interfaces: the address is always answered by this MAC address."
          :api="staticNeighbours"
          :params="{ instance_id: store.currentId }"
          :columns="staticColumns"
          :fields="staticFields"
          :defaults="{ enabled: true }"
          new-label="New static entry"
          :item-name="(r) => `static entry ${r.address}`"
          :search-text="(r) => (isV6(r.address) ? 'ND' : 'ARP')"
        />
      </template>
    </UTabs>
  </NeedInstance>
</template>
