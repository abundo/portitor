<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import DhcpClientLease from '@/components/DhcpClientLease.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { computed, ref } from 'vue'
import { interfaces } from '@/api'
import { useInstanceRefs, withLabel } from '@/composables/useInstanceRefs'
import { useDeployStore } from '@/stores/deploy'
import { bytes } from '@/utils/bytes'
import { useSearch } from '@/utils/search'

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
  { label: 'Loopback', value: 'loopback' },
]
// LLDP runs on the ethernet kinds.
const lldpKinds = ['physical', 'vlan', 'bridge']
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
    label: 'Virtual firewall',
    type: 'select',
    items: () => store.items,
    show: () => store.list.length > 1,
    hint: 'Changing it moves the interface to that virtual firewall, with its addresses. Its rules, routes and VLANs must go first; it leaves its interface zones.',
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
    items: (f) =>
      f.kind === 'wireguard' || f.kind === 'loopback'
        ? modes.filter((m) => m.value !== 'dhcp')
        : modes,
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
    hint: 'Addresses of the firewall on this interface with their prefix length, IPv4 and IPv6, as many as needed: 192.168.1.1/24, fd00:1::1/64. Their prefixes appear under Hosts & prefixes; DHCP and router advertisements are turned on for them under DHCP. An IPv6 address in the prefix delegated to another interface names it: <wan0>:2000::1/64 is subnet 2000 of the prefix wan0 gets, host ::1; its /64 is announced with router advertisements (SLAAC).',
  },
  { key: 'ipv6_accept_ra', label: 'IPv6 SLAAC (accept router advertisements)', type: 'switch' },
  {
    key: 'dhcpv6',
    label: 'DHCPv6 client',
    type: 'switch',
    show: (f) => f.kind !== 'wireguard' && f.kind !== 'loopback',
    hint: 'Ask a DHCPv6 server for an IPv6 address. Needs router advertisements accepted: the default route comes from them.',
  },
  {
    key: 'dhcpv6_pd',
    label: 'Prefix delegation',
    type: 'switch',
    show: (f) => f.dhcpv6,
    hint: 'Also ask for a delegated prefix, for the addresses of other interfaces written as <this interface>:subnet::host/64.',
  },
  {
    key: 'dhcpv6_pd_length',
    label: 'Delegated prefix length',
    type: 'number',
    show: (f) => f.dhcpv6 && f.dhcpv6_pd,
    hint: 'The prefix length to ask for, e.g. 56; 0 lets the server choose.',
  },
  {
    key: 'xlat464',
    label: '464XLAT',
    type: 'switch',
    show: (f) => f.kind !== 'loopback',
    hint: 'For clients with a CLAT (Android, iOS, macOS), which reach IPv4 over IPv6 only: router advertisements on this interface announce the NAT64 prefix (Network → NAT64; PREF64), and its DHCPv4 tells them IPv4 is not needed (option 108, IPv6-only preferred). Needs router advertisements on the interface (DHCP).',
  },
  { key: 'mtu', label: 'MTU', type: 'number', hint: '0 keeps the default.' },
  {
    key: 'lldp',
    label: 'LLDP',
    type: 'switch',
    show: (f) => lldpKinds.includes(f.kind),
    hint: 'Announce the firewall with LLDP on this interface and list the LLDP neighbours heard on it under Neighbours.',
  },
  {
    key: 'shape_egress',
    label: 'Shape upload (Mbit/s)',
    type: 'number',
    show: (f) => f.kind !== 'loopback',
    hint: 'Shapes what the interface sends with CAKE, a little below the line speed (95%), so the queue stays here instead of in the modem; 0 is off. When rules use a rate limit that shapes, an HTB tree at this rate replaces CAKE.',
  },
  {
    key: 'shape_ingress',
    label: 'Shape download (Mbit/s)',
    type: 'number',
    show: (f) => f.kind !== 'loopback',
    hint: 'Shapes what the interface receives (through an IFB device, ifb-<name>); 0 is off.',
  },
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
    hint: 'host:port written into generated client configs. Empty: the public endpoint host (WireGuard page) and the listen port.',
  },
  {
    key: 'wg_keepalive',
    label: 'Client keepalive (seconds)',
    type: 'number',
    show: (f) => f.kind === 'wireguard',
    hint: 'PersistentKeepalive in generated client configs; 0 disables it.',
  },
]

// The DHCP client's lease on the interface, if it runs one: DHCPv4
// (family '') or DHCPv6.
function leaseOf(row, family = '') {
  if (family === '' ? row.ipv4_mode !== 'dhcp' : !row.dhcpv6) return null
  return (
    deploy.status?.dhcp_client_leases?.find(
      (l) =>
        l.instance === store.current?.name &&
        l.interface === row.name &&
        (l.family ?? '') === family,
    ) ?? null
  )
}

// Interface statistics as the firewall reports them (the deploy store polls
// the agent's status), for the Statistics dialog.
const statsOpen = ref(false)
const statsRows = computed(() => {
  const inst = deploy.status?.instances?.find((i) => i.name === store.current?.name)
  return (inst?.interfaces ?? [])
    .map((i) => ({ ...i, label: ifaceText(i.name) }))
    .sort((a, b) => a.name.localeCompare(b.name))
})
// The counters, received then sent; bad ones show in warning colour when
// not zero.
const statsCols = [
  { key: 'rx_bytes', label: 'Bytes', bytes: true, first: true },
  { key: 'rx_packets', label: 'Packets' },
  { key: 'rx_errors', label: 'Errors', bad: true },
  { key: 'rx_dropped', label: 'Dropped', bad: true },
  { key: 'rx_over_errors', label: 'Overruns', bad: true },
  { key: 'rx_multicast', label: 'Multicast' },
  { key: 'tx_bytes', label: 'Bytes', bytes: true, first: true },
  { key: 'tx_packets', label: 'Packets' },
  { key: 'tx_errors', label: 'Errors', bad: true },
  { key: 'tx_dropped', label: 'Dropped', bad: true },
  { key: 'tx_carrier_errors', label: 'Carrier', bad: true },
  { key: 'tx_collisions', label: 'Collisions', bad: true },
]
const count = (n) => (n ?? 0).toLocaleString()
const { search: statsSearch, filtered: statsFiltered } = useSearch(statsRows)
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Interfaces"
      description="Physical ports, VLANs, bridges, loopbacks and WireGuard tunnels of this virtual firewall. Physical ports are moved into the virtual firewall's network namespace."
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
        dhcpv6: false,
        dhcpv6_pd: false,
        dhcpv6_pd_length: 0,
        lldp: false,
        xlat464: false,
        shape_egress: 0,
        shape_ingress: 0,
      }"
      new-label="New interface"
      @changed="reload()"
    >
      <template #toolbar-end>
        <UButton
          icon="i-lucide-chart-column"
          label="Statistics"
          color="neutral"
          variant="outline"
          @click="statsOpen = true"
        />
      </template>
      <template #cell-name="{ row }">
        <span class="font-mono font-medium">{{ row.name }}</span>
        <UTooltip v-if="isMissing(row)" text="Not found on the firewall">
          <UIcon name="i-lucide-triangle-alert" class="ml-1 align-middle text-warning" />
        </UTooltip>
      </template>
      <template #cell-addresses="{ row }">
        <DhcpClientLease :lease="leaseOf(row)" :no-default-route="row.dhcp_no_default_route" />
        <DhcpClientLease :lease="leaseOf(row, 'ipv6')" />
        <div v-for="a in row.addresses ?? []" :key="a" class="font-mono text-xs">
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
    <UModal
      v-model:open="statsOpen"
      title="Interface statistics"
      :dismissible="false"
      :ui="{
        content:
          'w-[calc(100vw-2rem)] max-w-none sm:max-w-none sm:w-[calc(100vw-4rem)] h-[calc(100dvh-2rem)] sm:h-[calc(100dvh-4rem)]',
        body: 'overflow-y-auto',
      }"
    >
      <template #body>
        <div class="space-y-3">
          <SearchInput v-model="statsSearch" />
          <div class="overflow-x-auto">
            <table class="w-full text-sm whitespace-nowrap">
              <thead class="text-muted">
                <tr>
                  <th colspan="4" />
                  <th colspan="6" class="border-l border-default px-2 py-1 text-center">
                    Received
                  </th>
                  <th colspan="6" class="border-l border-default px-2 py-1 text-center">Sent</th>
                </tr>
                <tr class="border-b border-default text-left">
                  <th class="px-2 py-1">Interface</th>
                  <th class="px-2 py-1">Kind</th>
                  <th class="px-2 py-1">State</th>
                  <th class="px-2 py-1">MTU</th>
                  <th
                    v-for="c in statsCols"
                    :key="c.key"
                    class="px-2 py-1 text-right"
                    :class="{ 'border-l border-default': c.first }"
                  >
                    {{ c.label }}
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="i in statsFiltered" :key="i.name" class="border-b border-default">
                  <td class="px-2 py-1 font-mono font-medium">{{ i.label }}</td>
                  <td class="px-2 py-1">{{ i.kind }}</td>
                  <td class="px-2 py-1">
                    <span :class="i.state === 'up' ? 'text-success' : 'text-muted'">
                      {{ i.state }}
                    </span>
                  </td>
                  <td class="px-2 py-1">{{ i.mtu }}</td>
                  <td
                    v-for="c in statsCols"
                    :key="c.key"
                    class="px-2 py-1 text-right font-mono"
                    :class="{
                      'border-l border-default': c.first,
                      'text-warning': c.bad && i[c.key],
                      'text-muted': !i[c.key],
                    }"
                  >
                    {{ c.bytes ? bytes(i[c.key] ?? 0) : count(i[c.key]) }}
                  </td>
                </tr>
                <tr v-if="!statsFiltered.length">
                  <td colspan="16" class="px-2 py-3 text-center text-muted">
                    {{
                      statsRows.length ? 'No matching interfaces.' : 'No status from the firewall.'
                    }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end">
          <UButton label="Close" color="neutral" variant="outline" @click="statsOpen = false" />
        </div>
      </template>
    </UModal>
  </NeedInstance>
</template>
