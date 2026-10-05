<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { interfaces } from '@/api'
import { useInstanceRefs, withLabel } from '@/composables/useInstanceRefs'
import { useDeployStore } from '@/stores/deploy'

// 6in4 tunnels (interfaces of kind 6in4), such as Hurricane Electric's
// tunnel broker, with the account that keeps the tunnel's IPv4 endpoint
// up to date.
const { store, reload } = useInstanceRefs()
const deploy = useDeployStore()

// The agent's endpoint updating of a tunnel, if it has an account.
function brokerOf(row) {
  return (
    deploy.status?.tunnel_broker?.find(
      (t) => t.instance === store.current?.name && t.interface === row.name,
    ) ?? null
  )
}
const stateColor = { ok: 'success', error: 'error', pending: 'neutral', 'dry-run': 'neutral' }

const columns = [
  { key: 'name', label: 'Interface', class: 'font-mono font-medium' },
  { key: 'label', label: 'Label', class: 'font-medium' },
  { key: 'tunnel_remote', label: 'Server', class: 'font-mono text-xs' },
  { key: 'addresses', label: 'Addresses' },
  {
    key: 'broker',
    label: 'Endpoint update',
    format: (r) => (r.he_tunnel_id ? (brokerOf(r)?.state ?? 'not deployed') : 'off'),
  },
  { key: 'enabled', label: 'Up' },
  { key: 'description', label: 'Description' },
]

const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'he0',
    hint: 'The Linux interface name of the tunnel.',
  },
  { key: 'label', label: 'Label', placeholder: 'HE' },
  { key: 'description', label: 'Description' },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'tunnel_heading', label: 'Tunnel', type: 'heading' },
  {
    key: 'tunnel_remote',
    label: 'Server IPv4 address',
    required: true,
    placeholder: '216.66.80.90',
    hint: "The tunnel server's IPv4 address (Server IPv4 Address on the tunnel's page at tunnelbroker.net). IPv6 in IPv4 (protocol 41) from and to it is accepted automatically.",
  },
  {
    key: 'tunnel_local',
    label: 'Local IPv4 address',
    placeholder: 'any',
    hint: "The firewall's IPv4 address the tunnel uses. Empty (any) for an address from DHCP, or behind NAT, where the router in front must forward protocol 41 to the firewall.",
  },
  {
    key: 'addresses',
    label: 'IPv6 addresses',
    type: 'tags',
    placeholder: '2001:470:1f0a:12::2/64',
    hint: "The firewall's end of the tunnel, with its prefix length (Client IPv6 Address). The routed prefixes go on LAN interfaces.",
  },
  {
    key: 'tunnel_default_route',
    label: 'IPv6 default route',
    type: 'switch',
    hint: 'Route IPv6 (::/0) through the tunnel, with metric 512: a static ::/0 under Routing → Static (metric 0) still wins, one from router advertisements (1024) loses.',
  },
  {
    key: 'mtu',
    label: 'MTU',
    type: 'number',
    hint: '0 keeps the default (1480). Must match the MTU set at tunnelbroker.net (Advanced tab).',
  },
  { key: 'broker_heading', label: 'Hurricane Electric tunnel broker', type: 'heading' },
  {
    key: 'he_tunnel_id',
    label: 'Tunnel ID',
    placeholder: '123456',
    hint: "Tells tunnelbroker.net the firewall's IPv4 address whenever it changes, so the tunnel follows a dynamic address. Empty turns it off. The Tunnel ID is on the tunnel's page.",
  },
  {
    key: 'he_username',
    label: 'User name',
    show: (f) => !!f.he_tunnel_id,
    hint: 'The tunnelbroker.net account’s user name.',
  },
  {
    key: 'new_he_update_key',
    label: 'Update key',
    type: 'password',
    show: (f) => !!f.he_tunnel_id,
    hint: "The tunnel's Update Key (Advanced tab). Stored on the server, never shown again; leave empty to keep the stored key.",
  },
]

const info =
  'IPv6 through an IPv6-in-IPv4 (6in4) tunnel, such as a free Hurricane Electric tunnel from tunnelbroker.net. ' +
  'The tunnel broker pings a new endpoint before it takes it; the firewall answers those pings by itself while it sends an update. The tunnel is an interface like any other, for rules, interface zones and routes. See Help → Tunnels.'
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Tunnels"
      noun="tunnel"
      description="6in4 tunnels (IPv6 in IPv4) to a tunnel broker, such as Hurricane Electric's, whose endpoint follows the firewall's IPv4 address."
      :info="info"
      :api="interfaces"
      :params="{ instance_id: store.currentId }"
      :row-filter="(r) => r.kind === '6in4'"
      :columns="columns"
      :fields="fields"
      :item-name="(r) => `tunnel ${withLabel(r.label, r.name)}`"
      :search-text="
        (r) => [brokerOf(r)?.address, brokerOf(r)?.last_error].filter(Boolean).join(' ')
      "
      :defaults="{
        kind: '6in4',
        label: '',
        enabled: true,
        ipv4_mode: 'none',
        addresses: [],
        members: [],
        mtu: 0,
        tunnel_remote: '',
        tunnel_local: '',
        tunnel_default_route: true,
        he_tunnel_id: '',
        he_username: '',
        new_he_update_key: '',
      }"
      new-label="New tunnel"
      @changed="reload()"
    >
      <template #cell-addresses="{ row }">
        <div v-for="a in row.addresses ?? []" :key="a" class="font-mono text-xs">{{ a }}</div>
      </template>
      <template #cell-broker="{ row }">
        <span v-if="!row.he_tunnel_id" class="text-muted">off</span>
        <span v-else-if="!brokerOf(row)" class="text-muted">not deployed</span>
        <div v-else class="space-y-0.5">
          <UBadge
            :label="brokerOf(row).state"
            :color="stateColor[brokerOf(row).state] ?? 'neutral'"
            variant="subtle"
            size="sm"
          />
          <span v-if="brokerOf(row).address" class="ml-1 font-mono text-xs">
            {{ brokerOf(row).address }}
          </span>
          <div v-if="brokerOf(row).last_error" class="text-xs text-error">
            {{ brokerOf(row).last_error }}
          </div>
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
