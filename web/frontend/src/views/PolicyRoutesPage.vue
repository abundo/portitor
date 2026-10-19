<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- Policy: policy routes of the virtual firewall, which route the forwarded
     traffic they match by a gateway or interface of their own. -->
<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { onMounted } from 'vue'
import { policyRoutes } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useObjectStore } from '@/stores/objects'

const { store, ifaceItems, ifaceName, ifaceListText, ifaceRefItems } = useInstanceRefs()
const objects = useObjectStore()
onMounted(() => objects.load().catch(() => {}))

const listText = (list) => (list?.length ? list.join(', ') : 'any')
const routeText = (r) => {
  const parts = [r.gateway, r.interface_id ? ifaceName(r.interface_id) : ''].filter(Boolean)
  return parts.length ? parts.join(' on ') : 'main table'
}

const columns = [
  { key: 'position', label: '#', format: (r, rows) => rows.indexOf(r) + 1 },
  { key: 'in_interfaces', label: 'Incoming', format: (r) => ifaceListText(r.in_interfaces) },
  { key: 'src_addrs', label: 'Source', class: 'font-mono', format: (r) => listText(r.src_addrs) },
  {
    key: 'dst_addrs',
    label: 'Destination',
    class: 'font-mono',
    format: (r) => listText(r.dst_addrs),
  },
  { key: 'services', label: 'Services', format: (r) => listText(r.services) },
  { key: 'gateway', label: 'Route', class: 'font-mono', format: routeText },
  { key: 'enabled', label: 'Enabled' },
  { key: 'description', label: 'Description' },
]
const fields = [
  { key: 'match_heading', label: 'Match', type: 'heading' },
  {
    key: 'in_interfaces',
    label: 'Incoming interfaces',
    type: 'multiselect',
    items: () => ifaceRefItems.value,
    placeholder: 'any',
    hint: 'Interfaces and interface zones; empty matches any. Interfaces in a VRF are not policy-routed.',
  },
  {
    key: 'family',
    label: 'IP version',
    type: 'select',
    items: [
      { label: 'any', value: 'any' },
      { label: 'IPv4', value: 'ipv4' },
      { label: 'IPv6', value: 'ipv6' },
    ],
    hint: 'The addresses and the gateway already decide it; needed only when they are any or IP lists.',
  },
  {
    key: 'src_addrs',
    label: 'Source addresses',
    type: 'addrs',
    lists: true,
    placeholder: '192.168.1.0/24, a name or @list',
  },
  {
    key: 'dst_addrs',
    label: 'Destination addresses',
    type: 'addrs',
    lists: true,
    placeholder: '203.0.113.0/24, a name or @list',
    hint: 'Matched before port forwards (DNAT) change the destination.',
  },
  {
    key: 'services',
    label: 'Services',
    type: 'multiselect',
    items: () => objects.serviceItems,
    placeholder: 'any',
    hint: 'The traffic must match one of them; empty matches any protocol.',
  },
  { key: 'route_heading', label: 'Route', type: 'heading' },
  {
    key: 'gateway',
    label: 'Gateway',
    type: 'addr',
    placeholder: '192.0.2.1 or a host',
    hint: 'A host with an IPv4 and an IPv6 address routes both; an address routes its IP version only. Neither gateway nor interface: the traffic keeps the main table (an exception to the policy routes below).',
  },
  {
    key: 'interface_id',
    label: 'Interface',
    type: 'select',
    items: () => ifaceItems.value,
    nullable: true,
    hint: 'Alone (a tunnel, WireGuard), it routes both IP versions out of the interface. Give it for a gateway on an interface with a DHCP address, so the policy route is passed over while that interface has no link.',
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
]

function policyName(r, rows) {
  const name = `policy route ${rows.findIndex((x) => x.id === r.id) + 1}`
  return r.description ? `${name} (${r.description})` : name
}

// Selects can't hold '' values; map 'any' <-> ''.
const api = {
  ...policyRoutes,
  list: async (p) => (await policyRoutes.list(p)).map(fromApi),
  create: async (b) => fromApi(await policyRoutes.create(clean(b))),
  update: async (id, b) => fromApi(await policyRoutes.update(id, clean(b))),
}
function fromApi(r) {
  return { ...r, family: r.family || 'any' }
}
function clean(b) {
  return { ...b, family: b.family === 'any' ? '' : b.family }
}
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Policy routes"
      noun="policy route"
      description="Route forwarded traffic by its source, destination, incoming interface or service, through a gateway or interface of its own instead of the routing table."
      info="Tried top to bottom; the first match decides, and drag the grip to reorder. A policy route without a gateway or interface is an exception: what it matches keeps the main table. While a policy route's gateway can't be reached (its interface down), its traffic takes the main table. Traffic from the firewall itself, and on interfaces in a VRF, isn't policy-routed. Traffic sent out of a second uplink needs source NAT there (a masquerade NAT rule), so its replies come back the same way. The firewall rules still decide what may pass."
      :api="api"
      :params="{ instance_id: store.currentId }"
      :columns="columns"
      :fields="fields"
      :defaults="{
        family: 'any',
        enabled: true,
        in_interfaces: [],
        src_addrs: [],
        dst_addrs: [],
        services: [],
        gateway: '',
        interface_id: null,
      }"
      new-label="New policy route"
      reorder="policy-routes"
      :item-name="policyName"
    />
  </NeedInstance>
</template>
