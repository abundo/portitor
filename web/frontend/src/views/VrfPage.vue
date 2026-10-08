<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- VRF: the VRFs of the virtual firewall. Interfaces are put in one on
     the Interfaces page, static routes on the Static page. A VRF with an
     L3VNI is an L3VPN over EVPN/VXLAN. -->
<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { vrfs } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'

const { store, ifaceList, vrfList, ifaceText, reload } = useInstanceRefs()

const membersOf = (name) =>
  ifaceList.value
    .filter((i) => i.vrf === name)
    .map((i) => ifaceText(i.name))
    .join(', ')

// The lowest table no VRF of the virtual firewall has, skipping the
// kernel's own (253-255): suggested for a new VRF.
function freeTable() {
  const used = new Set(vrfList.value.map((v) => v.route_table))
  let t = 1
  while (used.has(t) || (t >= 253 && t <= 255)) t++
  return t
}

const columns = [
  { key: 'name', label: 'Name', class: 'font-mono font-medium' },
  { key: 'route_table', label: 'Table' },
  { key: 'interfaces', label: 'Interfaces', format: (r) => membersOf(r.name) },
  {
    key: 'evpn_vni',
    label: 'L3VNI',
    format: (r) => (r.evpn_vni ? String(r.evpn_vni) : ''),
  },
  { key: 'description', label: 'Description' },
]
const hasEvpn = (f) => Number(f.evpn_vni) > 0
const ifaceItems = (f) =>
  [
    ...new Set(
      [
        ...ifaceList.value.filter((i) => !i.vrf && i.kind !== 'vxlan').map((i) => i.name),
        f.evpn_device,
      ].filter(Boolean),
    ),
  ].map((n) => ({ label: ifaceText(n), value: n }))
const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'blue',
    hint: 'The name of its Linux vrf device: at most 15 characters, not that of an interface or interface zone. Renaming it keeps its interfaces in it.',
  },
  {
    key: 'route_table',
    label: 'Table',
    type: 'number',
    required: true,
    hint: 'Its routing table, 1-6399 (not 253-255), unique in the virtual firewall; a new VRF gets the lowest free one. Other virtual firewalls may use the same name and table.',
  },
  { key: 'description', label: 'Description' },
  { key: 'evpn_heading', label: 'L3VPN (EVPN/VXLAN)', type: 'heading' },
  {
    key: 'evpn_vni',
    label: 'L3VNI',
    type: 'number',
    hint: "The VNI of the VRF's routes in EVPN (type-5 routes, symmetric IRB), 1-16777215, the same at every VTEP of the L3VPN and unique among the virtual firewall's VNIs; 0 is off. It needs BGP with EVPN in the main table (Routing → BGP), with the peers that carry it. The VRF gets a VXLAN device l3vx-<vni> in a bridge l3br-<vni>. Without BGP of its own, the VRF advertises its connected networks and static routes.",
  },
  {
    key: 'evpn_local',
    label: 'Local VTEP address',
    placeholder: '192.0.2.1',
    required: true,
    show: hasEvpn,
    hint: "The firewall's VTEP address, the source of the VXLAN packets: an address in the main table, often a loopback's, as for the VXLAN interfaces.",
  },
  {
    key: 'evpn_device',
    label: 'Underlay interface',
    type: 'select',
    nullable: true,
    text: true,
    items: ifaceItems,
    show: hasEvpn,
    hint: 'The interface the VXLAN packets leave by, and the only one they are accepted on. — : as routed, accepted on any.',
  },
  {
    key: 'evpn_port',
    label: 'UDP port',
    type: 'number',
    show: hasEvpn,
    hint: '0 is the standard port, 4789.',
  },
  { key: 'evpn_advertise_v4', label: 'Advertise IPv4', type: 'switch', show: hasEvpn },
  { key: 'evpn_advertise_v6', label: 'Advertise IPv6', type: 'switch', show: hasEvpn },
  {
    key: 'evpn_rd',
    label: 'Route distinguisher',
    placeholder: '192.0.2.1:100',
    show: hasEvpn,
    hint: "ASN:NN or IPv4:NN; empty: FRR's (router id:index).",
  },
  {
    key: 'evpn_import_rts',
    label: 'Import route targets',
    type: 'tags',
    placeholder: '65000:100',
    show: hasEvpn,
    hint: "The routes with one of these come into the VRF; ASN:NN or IPv4:NN. Empty: FRR's, AS:VNI.",
  },
  {
    key: 'evpn_export_rts',
    label: 'Export route targets',
    type: 'tags',
    placeholder: '65000:100',
    show: hasEvpn,
    hint: "The VRF's routes carry these; empty: FRR's, AS:VNI.",
  },
]
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="VRF"
      noun="VRF"
      description="VRFs of this virtual firewall: each routes the interfaces in it (Network → Interfaces) by its own table, apart from the main table and the other VRFs. Static routes go in one by their VRF or their interface's. With an L3VNI a VRF is an L3VPN over EVPN/VXLAN with the same VRFs at other VTEPs."
      :api="vrfs"
      :params="{ instance_id: store.currentId }"
      :columns="columns"
      :fields="fields"
      :search-text="(r) => membersOf(r.name)"
      :defaults="
        () => ({
          name: '',
          route_table: freeTable(),
          description: '',
          evpn_vni: 0,
          evpn_local: '',
          evpn_device: '',
          evpn_port: 0,
          evpn_rd: '',
          evpn_import_rts: [],
          evpn_export_rts: [],
          evpn_advertise_v4: true,
          evpn_advertise_v6: true,
        })
      "
      new-label="New VRF"
      :item-name="(r) => `VRF ${r.name}`"
      @changed="reload()"
    />
  </NeedInstance>
</template>
