<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { zones } from '@/api'
import { useInstanceStore } from '@/stores/instances'
import { actionColor } from '@/composables/useInstanceRefs'

const store = useInstanceStore()
const policies = ['accept', 'drop', 'reject'].map((v) => ({ label: v, value: v }))
const columns = [
  { key: 'name', label: 'Zone', class: 'font-medium' },
  { key: 'input_policy', label: 'Traffic to the firewall' },
  { key: 'masquerade', label: 'Masquerade (NAT) outgoing' },
  { key: 'description', label: 'Description' },
]
const fields = [
  { key: 'name', label: 'Name', required: true, placeholder: 'lan' },
  { key: 'description', label: 'Description' },
  {
    key: 'input_policy',
    label: 'Traffic to the firewall itself',
    type: 'select',
    items: policies,
    hint: 'Applied after the input rules. Typical: accept for LAN, drop for WAN.',
  },
  {
    key: 'masquerade',
    label: 'Masquerade IPv4 leaving through this zone',
    type: 'switch',
    hint: 'Turn on for the WAN zone.',
  },
]
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Zones"
      description="Zones group interfaces. Forwarding between zones is blocked unless a forward rule allows it."
      :api="zones"
      :params="{ instance_id: store.currentId }"
      :columns="columns"
      :fields="fields"
      :defaults="{ input_policy: 'drop', masquerade: false }"
      new-label="New zone"
    >
      <template #cell-input_policy="{ row }">
        <UBadge :color="actionColor[row.input_policy]" variant="subtle" :label="row.input_policy" />
      </template>
    </CrudPage>
  </NeedInstance>
</template>
