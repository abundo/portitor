<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ServicesPage: the services rules name in their Service column. Custom
// services are edited here (or created from a rule's Service cell); the
// predefined ones (netobj.Predefined) are listed below them, and last the
// built-in port names NAT port fields accept (fwconfig.Services).
import { computed, onMounted, ref } from 'vue'
import CrudPage from '@/components/CrudPage.vue'
import ServiceOptions from '@/components/ServiceOptions.vue'
import { customServices } from '@/api'
import { useObjectStore } from '@/stores/objects'
import { newService, serviceMatches, serviceTypes } from '@/utils/services'

const objects = useObjectStore()
onMounted(() => objects.load().catch(() => {}))

const typeLabel = (t) => serviceTypes.find((it) => it.value === t)?.label ?? t

const columns = [
  { key: 'name', label: 'Name', class: 'font-mono font-medium' },
  { key: 'type', label: 'Protocol type', format: (r) => typeLabel(r.type) },
  { key: 'match', label: 'Matches', class: 'font-mono' },
  { key: 'description', label: 'Description' },
]
const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'unifi',
    hint: "Lower case; a rule's Service cell takes it like ssh or ping.",
  },
  { key: 'description', label: 'Description' },
]

// filtered keeps the rows that have every word typed.
function filtered(list, words, text) {
  return list.filter((s) => words.every((w) => text(s).toLowerCase().includes(w)))
}

const filter = ref('')
const words = computed(() => filter.value.toLowerCase().split(/\s+/).filter(Boolean))
const predefined = computed(() =>
  filtered(
    objects.predefinedServices,
    words.value,
    (s) => `${s.name} ${serviceMatches(s).join(' ')} ${s.description}`,
  ),
)
const predefinedColumns = [
  { accessorKey: 'name', header: 'Name' },
  { accessorKey: 'type', header: 'Protocol type' },
  { id: 'match', header: 'Matches' },
  { accessorKey: 'description', header: 'Description' },
]

const portFilter = ref('')
const portNames = computed(() =>
  filtered(
    [...objects.services].sort((a, b) => a.name.localeCompare(b.name)),
    portFilter.value.toLowerCase().split(/\s+/).filter(Boolean),
    (s) => `${s.name} ${s.port} ${s.description}`,
  ),
)
const portColumns = [
  { accessorKey: 'name', header: 'Name' },
  { accessorKey: 'port', header: 'Port' },
  { accessorKey: 'description', header: 'Description' },
]
</script>

<template>
  <div class="space-y-6">
    <CrudPage
      title="Services"
      description="What a rule's Service column matches: a protocol with ports (TCP, UDP, SCTP), an ICMP or ICMPv6 type, or an IP protocol number. Next to your own services, the predefined ones below work too. Renaming updates every rule; a service in use cannot be deleted. A rule's Service cell can also create one."
      :api="customServices"
      :columns="columns"
      :fields="fields"
      :defaults="newService"
      new-label="New service"
      @changed="objects.load(true)"
    >
      <template #cell-match="{ row }">
        <span class="font-mono text-xs">{{ serviceMatches(row).join(', ') }}</span>
      </template>
      <template #form-extra="{ form }">
        <ServiceOptions :model-value="form" />
      </template>
    </CrudPage>

    <div class="card">
      <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div class="text-lg font-semibold">Predefined services</div>
          <p class="max-w-3xl text-sm text-muted">
            Built in; rules name them like your own services.
          </p>
        </div>
        <UInput v-model="filter" icon="i-lucide-search" placeholder="Filter" class="w-56" />
      </div>
      <UTable :data="predefined" :columns="predefinedColumns" class="text-sm">
        <template #name-cell="{ row }">
          <span class="font-mono font-medium">{{ row.original.name }}</span>
        </template>
        <template #type-cell="{ row }">{{ typeLabel(row.original.type) }}</template>
        <template #match-cell="{ row }">
          <span class="font-mono text-xs">{{ serviceMatches(row.original).join(', ') }}</span>
        </template>
        <template #empty>
          <div class="py-6 text-center text-muted">No service matches.</div>
        </template>
      </UTable>
    </div>

    <div class="card">
      <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div class="text-lg font-semibold">Port names</div>
          <p class="max-w-3xl text-sm text-muted">
            Well-known names from /etc/services that NAT port fields accept in place of a number.
            Where Debian and Fedora name a port differently, both names work.
          </p>
        </div>
        <UInput v-model="portFilter" icon="i-lucide-search" placeholder="Filter" class="w-56" />
      </div>
      <UTable :data="portNames" :columns="portColumns" class="text-sm">
        <template #name-cell="{ row }">
          <span class="font-mono font-medium">{{ row.original.name }}</span>
        </template>
        <template #port-cell="{ row }">
          <span class="font-mono tabular-nums">{{ row.original.port }}</span>
        </template>
        <template #empty>
          <div class="py-6 text-center text-muted">No port name matches.</div>
        </template>
      </UTable>
    </div>
  </div>
</template>
