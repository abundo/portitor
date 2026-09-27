<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, ref } from 'vue'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { interfaces, ipamAddresses } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'

const { store, zoneItems, zoneName, reload } = useInstanceRefs()
const addrs = ref([])

async function loadAddrs() {
  if (store.currentId) addrs.value = await ipamAddresses.list({ instance_id: store.currentId })
}
onMounted(loadAddrs)

const kinds = [
  { label: 'Physical', value: 'physical' },
  { label: 'VLAN', value: 'vlan' },
  { label: 'Bridge', value: 'bridge' },
  { label: 'WireGuard', value: 'wireguard' },
]
const modes = [
  { label: 'Static (from IP addresses)', value: 'static' },
  { label: 'DHCP client', value: 'dhcp' },
  { label: 'None', value: 'none' },
]

const columns = [
  { key: 'name', label: 'Interface', class: 'font-mono font-medium' },
  {
    key: 'kind',
    label: 'Kind',
    format: (r) => (r.kind === 'vlan' ? `vlan ${r.vlan_id} on ${r.parent}` : r.kind),
  },
  { key: 'zone_id', label: 'Zone', format: (r) => zoneName(r.zone_id) },
  { key: 'ipv4_mode', label: 'IPv4' },
  { key: 'addresses', label: 'Addresses' },
  { key: 'enabled', label: 'Up' },
  { key: 'description', label: 'Description' },
]

const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'eth0',
    hint: 'The Linux interface name.',
  },
  { key: 'kind', label: 'Kind', type: 'select', items: kinds, disabled: (f) => !!f.id },
  { key: 'description', label: 'Description' },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'parent', label: 'Parent interface', placeholder: 'eth1', show: (f) => f.kind === 'vlan' },
  { key: 'vlan_id', label: 'VLAN id', type: 'number', show: (f) => f.kind === 'vlan' },
  {
    key: 'members',
    label: 'Bridge members',
    type: 'tags',
    placeholder: 'eth2',
    show: (f) => f.kind === 'bridge',
  },
  {
    key: 'zone_id',
    label: 'Firewall zone',
    type: 'select',
    items: () => zoneItems.value,
    nullable: true,
  },
  {
    key: 'ipv4_mode',
    label: 'IPv4',
    type: 'select',
    items: (f) => (f.kind === 'wireguard' ? modes.filter((m) => m.value !== 'dhcp') : modes),
    hint: 'Static addresses are assigned under IP addresses.',
  },
  { key: 'ipv6_accept_ra', label: 'IPv6 SLAAC (accept router advertisements)', type: 'switch' },
  { key: 'dns_listen', label: 'DNS server answers on this interface', type: 'switch' },
  { key: 'mtu', label: 'MTU', type: 'number', hint: '0 keeps the default.' },
  {
    key: 'wg_listen_port',
    label: 'WireGuard listen port',
    type: 'number',
    show: (f) => f.kind === 'wireguard',
    hint: 'Opened automatically in the firewall. 0 for outgoing-only tunnels.',
  },
]

function addressesOf(row) {
  return addrs.value.filter((a) => a.interface_id === row.id).map((a) => a.address)
}
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Interfaces"
      description="Physical ports, VLANs, bridges and WireGuard tunnels of this instance. Physical ports are moved into the instance's network namespace."
      :api="interfaces"
      :params="{ instance_id: store.currentId }"
      :columns="columns"
      :fields="fields"
      :defaults="{
        kind: 'physical',
        enabled: true,
        ipv4_mode: 'static',
        members: [],
        mtu: 0,
        vlan_id: 0,
        wg_listen_port: 0,
      }"
      new-label="New interface"
      @changed="(reload(), loadAddrs())"
    >
      <template #cell-addresses="{ row }">
        <span class="font-mono text-xs">{{ addressesOf(row).join(', ') }}</span>
        <span v-if="row.ipv4_mode === 'dhcp'" class="text-xs text-muted"> (DHCP)</span>
      </template>
      <template #cell-enabled="{ row }">
        <UIcon
          :name="row.enabled ? 'i-lucide-circle-check' : 'i-lucide-circle-off'"
          :class="row.enabled ? 'text-success' : 'text-muted'"
        />
      </template>
    </CrudPage>
  </NeedInstance>
</template>
