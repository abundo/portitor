<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import RulesTable from '@/components/RulesTable.vue'
import { rules } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'

const { store, zoneItems } = useInstanceRefs()
const opt = (list) => list.map((v) => ({ label: v || 'any', value: v }))

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
  list: async (p) => (await rules.list(p)).map(fromApi),
  create: (b) => rules.create(clean(b)),
  update: async (id, b) => fromApi(await rules.update(id, clean(b))),
}
function fromApi(r) {
  return { ...r, family: r.family || 'any', protocol: r.protocol || 'any' }
}
function clean(b) {
  return {
    ...b,
    family: b.family === 'any' ? '' : b.family,
    protocol: b.protocol === 'any' ? '' : b.protocol,
  }
}
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Rules"
      description="Evaluated top to bottom; the first match decides. Edit cells in place (changes save at once), drag the grip to reorder. Established connections, DHCP/DNS for enabled services and WireGuard ports are allowed automatically. Forwarded traffic that no rule accepts is dropped."
      :api="api"
      :params="{ instance_id: store.currentId }"
      :columns="[]"
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
      <template #table="{ rows, openEdit, remove, moveTo, saveRow }">
        <RulesTable
          :rows="rows"
          :zones="zoneItems"
          @save="saveRow"
          @move="moveTo"
          @edit="openEdit"
          @remove="remove"
        />
      </template>
    </CrudPage>
  </NeedInstance>
</template>
