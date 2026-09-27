<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { rules } from '@/api'
import { actionColor, useInstanceRefs } from '@/composables/useInstanceRefs'

const { store, zoneItems, zoneName } = useInstanceRefs()
const opt = (list) => list.map((v) => ({ label: v || 'any', value: v }))

const columns = [
  { key: 'chain', label: 'Chain' },
  {
    key: 'from',
    label: 'From',
    format: (r) => (r.chain === 'output' ? 'firewall' : zoneName(r.src_zone_id) || 'any'),
  },
  {
    key: 'to',
    label: 'To',
    format: (r) => (r.chain === 'input' ? 'firewall' : zoneName(r.dst_zone_id) || 'any'),
  },
  { key: 'match', label: 'Match' },
  { key: 'action', label: 'Action' },
  { key: 'description', label: 'Description' },
]

const fields = [
  {
    key: 'chain',
    label: 'Traffic',
    type: 'select',
    items: [
      { label: 'forward: through the firewall', value: 'forward' },
      { label: 'input: to the firewall itself', value: 'input' },
      { label: 'output: from the firewall itself', value: 'output' },
    ],
  },
  {
    key: 'src_zone_id',
    label: 'From zone',
    type: 'select',
    items: () => zoneItems.value,
    nullable: true,
    show: (f) => f.chain !== 'output',
  },
  {
    key: 'dst_zone_id',
    label: 'To zone',
    type: 'select',
    items: () => zoneItems.value,
    nullable: true,
    show: (f) => f.chain !== 'input',
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
  },
  {
    key: 'protocol',
    label: 'Protocol',
    type: 'select',
    items: opt(['any', 'tcp', 'udp', 'icmp', 'icmpv6']),
  },
  {
    key: 'dst_ports',
    label: 'Destination ports',
    placeholder: '22, 80-90',
    show: (f) => f.protocol === 'tcp' || f.protocol === 'udp',
  },
  {
    key: 'src_addrs',
    label: 'Source addresses',
    type: 'addrs',
    placeholder: '192.168.1.0/24 or a name',
  },
  {
    key: 'dst_addrs',
    label: 'Destination addresses',
    type: 'addrs',
    placeholder: '192.168.1.10 or a name',
    hint: 'Addresses, CIDRs or hosts/prefixes. With IPv4 and IPv6 entries the rule applies to both.',
  },
  { key: 'action', label: 'Action', type: 'select', items: opt(['accept', 'drop', 'reject']) },
  { key: 'log', label: 'Log matches', type: 'switch' },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
]

// Selects can't hold '' values; map 'any' <-> ''.
const api = {
  ...rules,
  list: async (p) =>
    (await rules.list(p)).map((r) => ({
      ...r,
      family: r.family || 'any',
      protocol: r.protocol || 'any',
    })),
  create: (b) => rules.create(clean(b)),
  update: (id, b) => rules.update(id, clean(b)),
}
function clean(b) {
  return {
    ...b,
    family: b.family === 'any' ? '' : b.family,
    protocol: b.protocol === 'any' ? '' : b.protocol,
  }
}

function match(r) {
  const parts = []
  if (r.family !== 'any') parts.push(r.family)
  if (r.protocol !== 'any') parts.push(r.protocol + (r.dst_ports ? ` ${r.dst_ports}` : ''))
  if (r.src_addrs?.length) parts.push(`from ${r.src_addrs.join(', ')}`)
  if (r.dst_addrs?.length) parts.push(`to ${r.dst_addrs.join(', ')}`)
  return parts.join(' · ') || 'all traffic'
}
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Rules"
      description="Evaluated top to bottom; the first match decides. Established connections, DHCP/DNS for enabled services and WireGuard ports are allowed automatically. Forwarded traffic that no rule accepts is dropped."
      :api="api"
      :params="{ instance_id: store.currentId }"
      :columns="columns"
      :fields="fields"
      :defaults="{
        chain: 'forward',
        family: 'any',
        protocol: 'any',
        action: 'accept',
        enabled: true,
        log: false,
        src_addrs: [],
        dst_addrs: [],
      }"
      new-label="New rule"
      reorder="rules"
      :item-name="(r) => `rule ${r.description || r.id}`"
    >
      <template #cell-match="{ row }">
        <span class="text-xs">{{ match(row) }}</span>
      </template>
      <template #cell-action="{ row }">
        <div class="flex items-center gap-1">
          <UBadge :color="actionColor[row.action]" variant="subtle" :label="row.action" />
          <UIcon v-if="row.log" name="i-lucide-scroll-text" class="text-muted" title="logged" />
          <UBadge v-if="!row.enabled" color="neutral" variant="outline" label="off" />
        </div>
      </template>
    </CrudPage>
  </NeedInstance>
</template>
