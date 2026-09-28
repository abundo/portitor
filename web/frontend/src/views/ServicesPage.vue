<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ServicesPage: the port names that rule and NAT port fields accept. Custom
// services are edited here (or created from a port field's menu); the
// built-in ones (fwconfig.Services) are listed below them.
import { computed, onMounted, ref } from 'vue'
import CrudPage from '@/components/CrudPage.vue'
import { customServices } from '@/api'
import { useObjectStore } from '@/stores/objects'

const objects = useObjectStore()
onMounted(() => objects.load().catch(() => {}))

const columns = [
  { key: 'name', label: 'Name', class: 'font-mono font-medium' },
  { key: 'ports', label: 'Ports', class: 'font-mono' },
  { key: 'description', label: 'Description' },
]
const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'unifi',
    hint: 'Lower case; port fields take it like ssh or https.',
  },
  {
    key: 'ports',
    label: 'Ports',
    required: true,
    placeholder: '8080, 8443',
    hint: 'A port (8443), a range (8000-8080) or several (8080, 8443, 10001). Built-in service names work too.',
  },
  { key: 'description', label: 'Description' },
]

// The built-in services by name, filtered by the words typed.
const filter = ref('')
const builtin = computed(() => {
  const words = filter.value.toLowerCase().split(/\s+/).filter(Boolean)
  return [...objects.services]
    .sort((a, b) => a.name.localeCompare(b.name))
    .filter((s) => {
      const text = `${s.name} ${s.port} ${s.description}`.toLowerCase()
      return words.every((w) => text.includes(w))
    })
})
const builtinColumns = [
  { accessorKey: 'name', header: 'Name' },
  { accessorKey: 'port', header: 'Port' },
  { accessorKey: 'description', header: 'Description' },
]
</script>

<template>
  <div class="space-y-6">
    <CrudPage
      title="Services"
      description="Named ports for the destination ports of rules and NAT, next to the built-in names below. A service can hold one port, a range or several ports. Renaming updates every use; a service in use cannot be deleted. A port field's menu can also create one."
      :api="customServices"
      :columns="columns"
      :fields="fields"
      :defaults="{ ports: '' }"
      new-label="New service"
      @changed="objects.load(true)"
    />

    <div class="card">
      <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div class="text-lg font-semibold">Built-in services</div>
          <p class="max-w-3xl text-sm text-muted">
            Well-known names from /etc/services. Where Debian and Fedora name a port differently,
            both names work.
          </p>
        </div>
        <UInput v-model="filter" icon="i-lucide-search" placeholder="Filter" class="w-56" />
      </div>
      <UTable :data="builtin" :columns="builtinColumns" class="text-sm">
        <template #name-cell="{ row }">
          <span class="font-mono font-medium">{{ row.original.name }}</span>
        </template>
        <template #port-cell="{ row }">
          <span class="font-mono tabular-nums">{{ row.original.port }}</span>
        </template>
        <template #empty>
          <div class="py-6 text-center text-muted">No service matches.</div>
        </template>
      </UTable>
    </div>
  </div>
</template>
