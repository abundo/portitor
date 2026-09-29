<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import { addressObjects } from '@/api'
import { useObjectStore } from '@/stores/objects'

const objects = useObjectStore()

// A host has only single addresses (/32, /128); anything else is a prefix.
const single = (a) => !a.includes('/') || a.endsWith('/32') || a.endsWith('/128')
const kind = (o) => (o.addresses?.length && o.addresses.every(single) ? 'host' : 'prefix')
const versions = (o) => {
  const v6 = o.addresses?.some((a) => a.includes(':'))
  const v4 = o.addresses?.some((a) => !a.includes(':'))
  return v4 && v6 ? 'IPv4 + IPv6' : v6 ? 'IPv6' : 'IPv4'
}

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'kind', label: 'Kind' },
  { key: 'addresses', label: 'Addresses', class: 'font-mono text-xs' },
  { key: 'versions', label: 'IP version', format: versions },
  { key: 'description', label: 'Description' },
]
const fields = [
  { key: 'name', label: 'Name', required: true, placeholder: 'nas' },
  {
    key: 'addresses',
    label: 'Addresses and prefixes',
    type: 'tags',
    placeholder: '192.168.1.10, fd00:1::10',
    hint: 'Give a host both its IPv4 and IPv6 address: a rule using it then covers both.',
  },
  { key: 'description', label: 'Description' },
]
</script>

<template>
  <CrudPage
    title="Hosts & prefixes"
    noun="host or prefix"
    description="Named addresses. Use the name wherever addresses are entered: rules, NAT, routes, DNS, DHCP and WireGuard. A rule whose addresses include IPv4 and IPv6 is applied to both. Renaming updates every use; a name in use cannot be deleted."
    :api="addressObjects"
    :columns="columns"
    :fields="fields"
    :defaults="{ addresses: [] }"
    new-label="New host/prefix"
    @changed="objects.load(true)"
  >
    <template #cell-kind="{ row }">
      <UBadge
        :color="kind(row) === 'host' ? 'primary' : 'neutral'"
        variant="subtle"
        :label="kind(row)"
      />
    </template>
  </CrudPage>
</template>
