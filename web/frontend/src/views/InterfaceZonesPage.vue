<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { interfaceZones } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'

const { store, ifaceNames, reload } = useInstanceRefs()
const columns = [
  { key: 'name', label: 'Zone', class: 'font-medium' },
  { key: 'interfaces', label: 'Interfaces' },
  { key: 'description', label: 'Description' },
]
const fields = [
  { key: 'name', label: 'Name', required: true, placeholder: 'lan' },
  { key: 'description', label: 'Description' },
  {
    key: 'interfaces',
    label: 'Interfaces',
    type: 'multiselect',
    items: () => ifaceNames.value,
    placeholder: 'none',
    hint: 'Zero or more interfaces of this instance, link ends included. An interface may be in several zones.',
  },
]
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Interface zones"
      description="Named groups of interfaces. Rules and NAT rules can name a zone wherever they list interfaces. A rule whose interfaces are all in empty zones (or disabled) is left out, never widened to any interface."
      :api="interfaceZones"
      :params="{ instance_id: store.currentId }"
      :columns="columns"
      :fields="fields"
      :defaults="{ interfaces: [] }"
      new-label="New interface zone"
      @changed="reload"
    >
      <template #cell-interfaces="{ row }">
        <span v-if="row.interfaces?.length" class="font-mono text-xs">{{
          row.interfaces.join(', ')
        }}</span>
        <span v-else class="text-xs text-muted italic">empty</span>
      </template>
    </CrudPage>
  </NeedInstance>
</template>
