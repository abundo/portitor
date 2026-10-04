<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// NatTable lists the NAT rules of one hook: prerouting holds the port
// forwards (DNAT), postrouting source NAT and masquerade. The rules page
// shows each in its tab, in the order packets pass the hooks.
import CrudPage from '@/components/CrudPage.vue'
import { nat } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'

const props = defineProps({
  // 'prerouting' or 'postrouting'
  hook: { type: String, required: true },
  description: { type: String, default: '' },
})

const { store, ifaceRefItems, ifaceListText } = useInstanceRefs()

const pre = props.hook === 'prerouting'
const kinds = pre
  ? [{ label: 'Port forward (DNAT)', value: 'dnat' }]
  : [
      { label: 'Masquerade', value: 'masquerade' },
      { label: 'Source NAT to fixed address (SNAT)', value: 'snat' },
    ]
const ofHook = (r) => (r.kind === 'dnat') === pre
const protos = [
  { label: 'any', value: 'any' },
  { label: 'tcp', value: 'tcp' },
  { label: 'udp', value: 'udp' },
  { label: 'tcp+udp', value: 'tcp,udp' },
]
const protoLabel = (p) => (p === 'tcp,udp' ? 'tcp+udp' : p)
// natIfaces returns the interface list a NAT rule matches on, by its kind.
const natIfaces = (r) => (r.kind === 'dnat' ? r.in_interfaces : r.out_interfaces)
const natIfacesLabel = (r) => `${r.kind === 'dnat' ? 'in' : 'out'}: ${ifaceListText(natIfaces(r))}`

// natNo numbers a NAT rule by its place in its hook's list; natName names
// it: "prerouting rule 3 (description)".
const natNo = (r, rows) => rows.findIndex((x) => x.id === r.id) + 1
function natName(r, rows) {
  const name = `${props.hook} rule ${natNo(r, rows)}`
  return r.description ? `${name} (${r.description})` : name
}

const columns = [
  { key: 'no', label: '#', format: natNo, class: 'text-muted tabular-nums' },
  ...(pre ? [] : [{ key: 'kind', label: 'Kind' }]),
  {
    key: 'ifaces',
    label: 'Interfaces',
    format: natIfacesLabel,
  },
  {
    key: 'match',
    label: 'Match',
    format: (r) =>
      [
        r.protocol !== 'any' ? protoLabel(r.protocol) : '',
        r.dst_ports,
        r.src_addrs?.length ? `from ${r.src_addrs.join(', ')}` : '',
        r.dst_addrs?.length ? `to ${r.dst_addrs.join(', ')}` : '',
      ]
        .filter(Boolean)
        .join(' '),
  },
  {
    key: 'target',
    label: 'Translate to',
    class: 'font-mono',
    format: (r) =>
      r.kind === 'masquerade'
        ? 'interface address'
        : r.to_addr + (r.to_port ? `:${r.to_port}` : ''),
  },
  { key: 'enabled', label: 'Enabled' },
  { key: 'description', label: 'Description' },
]
const fields = [
  ...(pre ? [] : [{ key: 'kind', label: 'Kind', type: 'select', items: kinds }]),
  {
    key: 'in_interfaces',
    label: 'Incoming interfaces',
    type: 'multiselect',
    items: () => ifaceRefItems.value,
    placeholder: 'any',
    show: (f) => f.kind === 'dnat',
    hint: 'Interfaces and interface zones; usually the WAN.',
  },
  {
    key: 'out_interfaces',
    label: 'Outgoing interfaces',
    type: 'multiselect',
    items: () => ifaceRefItems.value,
    placeholder: 'any',
    show: (f) => f.kind !== 'dnat',
    hint: 'Interfaces and interface zones; for Internet sharing, masquerade out of the WAN.',
  },
  { key: 'protocol', label: 'Protocol', type: 'select', items: protos },
  {
    key: 'dst_ports',
    label: 'Destination ports',
    type: 'ports',
    placeholder: '8443 or https',
    show: (f) => f.protocol !== 'any',
  },
  { key: 'src_addrs', label: 'Source addresses', type: 'addrs' },
  { key: 'dst_addrs', label: 'Destination addresses', type: 'addrs' },
  {
    key: 'to_addr',
    label: 'Target address',
    type: 'addr',
    placeholder: '192.168.1.10 or a host',
    show: (f) => f.kind !== 'masquerade',
    hint: 'A host with an IPv4 and an IPv6 address makes one rule for each.',
  },
  {
    key: 'to_port',
    label: 'Target port',
    type: 'number',
    show: (f) => f.kind === 'dnat' && f.protocol !== 'any',
    hint: '0 keeps the original port.',
  },
  {
    key: 'hairpin',
    label: 'Hairpin',
    type: 'switch',
    show: (f) => f.kind === 'dnat',
    hint: "Also forward connections from the other interfaces to the firewall's own addresses (the LAN reaching a server by its public address), masqueraded so replies return through the firewall.",
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
]
const api = {
  ...nat,
  list: async (p) => (await nat.list(p)).map((r) => ({ ...r, protocol: r.protocol || 'any' })),
  create: (b) => nat.create({ ...b, protocol: b.protocol === 'any' ? '' : b.protocol }),
  update: (id, b) => nat.update(id, { ...b, protocol: b.protocol === 'any' ? '' : b.protocol }),
}
</script>

<template>
  <CrudPage
    bare
    title="NAT"
    :noun="pre ? 'port forward' : 'source NAT rule'"
    :description="description"
    :api="api"
    :params="{ instance_id: store.currentId }"
    :row-filter="ofHook"
    :columns="columns"
    :fields="fields"
    :defaults="{
      kind: pre ? 'dnat' : 'masquerade',
      protocol: pre ? 'tcp' : 'any',
      enabled: true,
      in_interfaces: [],
      out_interfaces: [],
      src_addrs: [],
      dst_addrs: [],
      to_port: 0,
      hairpin: false,
    }"
    :new-label="pre ? 'New port forward' : 'New source NAT rule'"
    reorder="nat"
    :item-name="natName"
  />
</template>
