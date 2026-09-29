<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { interfaces } from '@/api'
import { useInstanceRefs, withLabel } from '@/composables/useInstanceRefs'
import { useDeployStore } from '@/stores/deploy'

const { store, ifaceList, ifaceText, zonesOf, reload } = useInstanceRefs()
const deploy = useDeployStore()
const isMissing = (row) =>
  row.kind === 'physical' &&
  deploy.missingNics.some((n) => n.name === row.name && n.instance === store.current?.name)
// The MAC address the firewall reports; a physical port not yet moved into
// the instance is looked up among all NICs.
function macOf(row) {
  const inst = deploy.status?.instances?.find((i) => i.name === store.current?.name)
  const mac = inst?.interfaces?.find((i) => i.name === row.name)?.mac
  if (mac || row.kind !== 'physical') return mac ?? ''
  return deploy.status?.nics?.find((n) => n.name === row.name)?.mac ?? ''
}

const kinds = [
  { label: 'Physical', value: 'physical' },
  { label: 'VLAN', value: 'vlan' },
  { label: 'Bridge', value: 'bridge' },
  { label: 'WireGuard', value: 'wireguard' },
]
const modes = [
  { label: 'Static', value: 'static' },
  { label: 'DHCP client', value: 'dhcp' },
  { label: 'None', value: 'none' },
]

const columns = [
  { key: 'name', label: 'Interface', class: 'font-mono font-medium' },
  { key: 'label', label: 'Label', class: 'font-medium' },
  {
    key: 'kind',
    label: 'Kind',
    format: (r) => (r.kind === 'vlan' ? `vlan ${r.vlan_id} on ${ifaceText(r.parent)}` : r.kind),
  },
  { key: 'mac', label: 'MAC', class: 'font-mono text-xs', format: macOf },
  { key: 'zones', label: 'Zones', format: (r) => zonesOf(r.name).join(', ') },
  { key: 'ipv4_mode', label: 'IPv4' },
  { key: 'addresses', label: 'Addresses' },
  { key: 'enabled', label: 'Up' },
  { key: 'description', label: 'Description' },
]

// Other interfaces of the instance, as items that show their labels, for a
// VLAN's parent and a bridge's members; a name the form holds but the
// instance lacks stays listed.
function otherIfaces(f, keep = []) {
  const names = ifaceList.value.filter((i) => i.id !== f.id).map((i) => i.name)
  return [...new Set([...names, ...keep.filter(Boolean)])].map((n) => ({
    label: ifaceText(n),
    value: n,
  }))
}

const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'eth0',
    hint: 'The Linux interface name.',
  },
  {
    key: 'label',
    label: 'Label',
    placeholder: 'WAN',
    hint: 'A short name shown before the interface name wherever an interface is picked: WAN (ens18).',
  },
  {
    key: 'instance_id',
    label: 'Instance',
    type: 'select',
    items: () => store.items,
    show: () => store.list.length > 1,
    hint: 'Changing it moves the interface to that instance, with its addresses. Its rules, routes and VLANs must go first; it leaves its interface zones.',
  },
  { key: 'kind', label: 'Kind', type: 'select', items: kinds, disabled: (f) => !!f.id },
  { key: 'description', label: 'Description' },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  {
    key: 'parent',
    label: 'Parent interface',
    type: 'select',
    items: (f) => otherIfaces(f, [f.parent]),
    show: (f) => f.kind === 'vlan',
  },
  { key: 'vlan_id', label: 'VLAN id', type: 'number', show: (f) => f.kind === 'vlan' },
  {
    key: 'members',
    label: 'Bridge members',
    type: 'multiselect',
    items: (f) => otherIfaces(f),
    show: (f) => f.kind === 'bridge',
  },
  {
    key: 'ipv4_mode',
    label: 'IPv4',
    type: 'select',
    items: (f) => (f.kind === 'wireguard' ? modes.filter((m) => m.value !== 'dhcp') : modes),
    hint: 'Static: the addresses below. DHCP client: IPv4 from a DHCP server, and no addresses below.',
  },
  {
    key: 'dhcp_no_default_route',
    label: 'No default route from DHCP',
    type: 'switch',
    show: (f) => f.ipv4_mode === 'dhcp',
    hint: 'Ignore the router the DHCP server offers, e.g. on a LAN; the default route comes from the WAN.',
  },
  {
    key: 'addresses',
    label: 'IP addresses',
    type: 'tags',
    placeholder: '192.168.1.1/24',
    disabled: (f) => f.ipv4_mode === 'dhcp',
    hint: 'Addresses of the firewall on this interface with their prefix length, IPv4 and IPv6, as many as needed: 192.168.1.1/24, fd00:1::1/64. Their prefixes appear under IP addresses, where DHCP and router advertisements are turned on per prefix.',
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
  {
    key: 'wg_endpoint',
    label: 'Public endpoint for clients',
    placeholder: 'vpn.example.org:51820',
    show: (f) => f.kind === 'wireguard',
    hint: 'host:port written into generated client configs. Empty: the endpoint host under Settings and the listen port.',
  },
  {
    key: 'wg_keepalive',
    label: 'Client keepalive (seconds)',
    type: 'number',
    show: (f) => f.kind === 'wireguard',
    hint: 'PersistentKeepalive in generated client configs; 0 disables it.',
  },
]

// The address the DHCP client holds on the interface, if it has one.
function dhcpAddressOf(row) {
  if (row.ipv4_mode !== 'dhcp') return ''
  const lease = deploy.status?.dhcp_client_leases?.find(
    (l) => l.instance === store.current?.name && l.interface === row.name,
  )
  return lease?.state === 'bound' ? lease.address : ''
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
      :item-name="(r) => `interface ${withLabel(r.label, r.name)}`"
      :defaults="{
        kind: 'physical',
        label: '',
        enabled: true,
        ipv4_mode: 'static',
        addresses: [],
        members: [],
        mtu: 0,
        vlan_id: 0,
        wg_listen_port: 0,
        wg_endpoint: '',
        wg_keepalive: 25,
      }"
      new-label="New interface"
      @changed="reload()"
    >
      <template #cell-name="{ row }">
        <span class="font-mono font-medium">{{ row.name }}</span>
        <UTooltip v-if="isMissing(row)" text="Not found on the firewall">
          <UIcon name="i-lucide-triangle-alert" class="ml-1 align-middle text-warning" />
        </UTooltip>
      </template>
      <template #cell-addresses="{ row }">
        <div
          v-for="a in [dhcpAddressOf(row), ...(row.addresses ?? [])].filter(Boolean)"
          :key="a"
          class="font-mono text-xs"
        >
          {{ a }}
        </div>
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
