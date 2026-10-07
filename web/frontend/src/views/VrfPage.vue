<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- VRF: the VRFs of the virtual firewall. Interfaces are put in one on
     the Interfaces page, static routes on the Static page. -->
<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { vrfs } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'

const { store, ifaceList, ifaceText, reload } = useInstanceRefs()

const membersOf = (name) =>
  ifaceList.value
    .filter((i) => i.vrf === name)
    .map((i) => ifaceText(i.name))
    .join(', ')

const columns = [
  { key: 'name', label: 'Name', class: 'font-mono font-medium' },
  { key: 'route_table', label: 'Table' },
  { key: 'interfaces', label: 'Interfaces', format: (r) => membersOf(r.name) },
  { key: 'description', label: 'Description' },
]
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
    hint: 'Its routing table, 1-6399 (not 253-255), unique in the virtual firewall. Other virtual firewalls may use the same name and table.',
  },
  { key: 'description', label: 'Description' },
]
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="VRF"
      noun="VRF"
      description="VRFs of this virtual firewall: each routes the interfaces in it (Network → Interfaces) by its own table, apart from the main table and the other VRFs. Static routes go in one by their VRF or their interface's."
      :api="vrfs"
      :params="{ instance_id: store.currentId }"
      :columns="columns"
      :fields="fields"
      :search-text="(r) => membersOf(r.name)"
      :defaults="{ name: '', route_table: 0, description: '' }"
      new-label="New VRF"
      :item-name="(r) => `VRF ${r.name}`"
      @changed="reload()"
    />
  </NeedInstance>
</template>
