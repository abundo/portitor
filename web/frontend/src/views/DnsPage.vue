<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref } from 'vue'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { dnsTemplates, dnsZones } from '@/api'
import { useInstanceStore } from '@/stores/instances'
import { zoneTypes } from '@/utils/dns'

const store = useInstanceStore()
const instance = computed(() => store.current)
const templates = ref([])

onMounted(async () => {
  templates.value = await dnsTemplates.list()
})

const typeLabel = (t) => zoneTypes.find((x) => x.value === t)?.label ?? t
const zoneColumns = [
  { key: 'name', label: 'Zone', class: 'font-mono font-medium' },
  { key: 'type', label: 'Type', format: (r) => typeLabel(r.type) },
  {
    key: 'template',
    label: 'DNS template',
    format: (r) => templates.value.find((t) => t.id === r.dns_template_id)?.name ?? 'built-in',
  },
  { key: 'description', label: 'Description' },
]
const zoneFields = [
  { key: 'type', label: 'Type', type: 'select', items: zoneTypes },
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'home.arpa, or 192.168.1.0/24 for reverse',
  },
  {
    key: 'dns_template_id',
    label: 'DNS template',
    type: 'select',
    nullable: true,
    items: () => templates.value.map((t) => ({ label: t.name, value: t.id })),
    hint: 'SOA, NS and default TTL come from the template. —: built-in (NS localhost).',
  },
  { key: 'description', label: 'Description' },
]
const zoneDefaults = () => ({ type: 'forward', dns_template_id: templates.value[0]?.id ?? null })
</script>

<template>
  <NeedInstance>
    <div class="space-y-4">
      <UAlert
        v-if="instance && !instance.dns_enabled"
        color="warning"
        variant="subtle"
        icon="i-lucide-triangle-alert"
        title="The DNS server is off for this instance"
        description="Zones are kept but not served. Turn it on under Instances."
      />
      <CrudPage
        title="DNS zones"
        description="Zones served by this instance's DNS server (BIND, via dnsmgr2). Names of IPAM addresses go into the matching forward zone; PTRs in reverse zones are generated. Open a zone to edit its records."
        :api="dnsZones"
        :params="{ instance_id: store.currentId }"
        :columns="zoneColumns"
        :fields="zoneFields"
        :defaults="zoneDefaults"
        new-label="New zone"
      >
        <template #toolbar>
          <UButton
            to="/dns/templates"
            color="neutral"
            variant="outline"
            icon="i-lucide-file-cog"
            label="Templates"
          />
        </template>
        <template #cell-name="{ row }">
          <RouterLink class="font-mono font-medium text-primary" :to="`/dns/zones/${row.id}`">
            {{ row.name }}
          </RouterLink>
        </template>
      </CrudPage>
    </div>
  </NeedInstance>
</template>
