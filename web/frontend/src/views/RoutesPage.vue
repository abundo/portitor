<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- Static: the static routes of the virtual firewall. The routing tables
     as the kernel has them are on the Routing page. -->
<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { computed } from 'vue'
import { routes } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'

const { store, vrfList, ifaceItems, ifaceName } = useInstanceRefs()

const vrfItems = computed(() => vrfList.value.map((v) => ({ label: v.name, value: v.id })))
const vrfName = (id) => vrfList.value.find((v) => v.id === id)?.name ?? ''

const columns = [
  { key: 'destination', label: 'Destination', class: 'font-mono' },
  { key: 'gateway', label: 'Gateway', class: 'font-mono' },
  { key: 'interface_id', label: 'Interface', format: (r) => ifaceName(r.interface_id) },
  { key: 'vrf_id', label: 'VRF', format: (r) => vrfName(r.vrf_id) },
  { key: 'metric', label: 'Metric' },
  { key: 'bfd', label: 'BFD' },
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
    key: 'vrf_id',
    label: 'VRF',
    type: 'select',
    items: () => vrfItems.value,
    nullable: true,
    show: (f) => vrfItems.value.length > 0 || !!f.vrf_id,
    hint: 'Puts the route in the VRF’s table. — : the table of the interface’s VRF, or the main table.',
  },
  {
    key: 'metric',
    label: 'Metric',
    type: 'number',
    hint: 'DHCP default routes use metric 100, so a static default with a lower metric wins. With BFD: FRR’s administrative distance (0-255).',
  },
  {
    key: 'bfd',
    label: 'BFD',
    type: 'switch',
    hint: 'Withdraws the route while BFD loses the gateway, when the gateway’s interface has BFD (Routing → BFD). The route is then FRR’s.',
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
]
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Static routes"
      description="Static routes of this virtual firewall. Connected networks and DHCP default routes are added automatically."
      :api="routes"
      :params="{ instance_id: store.currentId }"
      :columns="columns"
      :fields="fields"
      :defaults="{ enabled: true, metric: 0, bfd: false }"
      new-label="New route"
      :item-name="(r) => `route ${r.destination}`"
    />
  </NeedInstance>
</template>
