<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- Neighbours: what the instance's interfaces see next to them, by
     interface: the LLDP neighbours heard (an info button shows all their
     frame said), then the ARP (IPv4) and ND (IPv6) entries. -->
<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useSearch, valuesText } from '@/utils/search'
import { ago, when } from '@/utils/time'

const { store, ifaceNames, ifaceText } = useInstanceRefs()
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
let timer = null
onMounted(() => {
  load()
  timer = setInterval(load, 10000)
})
onBeforeUnmount(() => clearInterval(timer))

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
  return out.sort(
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
  valuesText(ifaceText(r.interface), protoLabel[r.kind], r.neighbour, r.address, r.mac, r.details),
)

const columns = [
  { id: 'info', header: '' },
  { id: 'interface', header: 'Interface' },
  { id: 'kind', header: 'Protocol' },
  { accessorKey: 'neighbour', header: 'Name' },
  { accessorKey: 'address', header: 'Address' },
  { accessorKey: 'mac', header: 'MAC' },
  { accessorKey: 'details', header: 'Port / state' },
]

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
</script>

<template>
  <NeedInstance>
    <div class="card">
      <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div class="text-lg font-semibold">Neighbours</div>
          <p class="max-w-3xl text-sm text-muted">
            What this instance's interfaces see next to them: LLDP neighbours, on the interfaces
            with LLDP turned on under
            <RouterLink to="/interfaces" class="text-primary">Interfaces</RouterLink>, and the ARP
            (IPv4) and ND (IPv6) tables.
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
  </NeedInstance>
</template>
