<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- Everything FRR has on one BGP neighbour (`show bgp neighbors <n>
     json`): as a table of fields, nested objects flattened into dotted
     names, and as FRR's JSON. Read-only. -->
<script setup>
import { computed, ref, watch } from 'vue'
import SearchInput from '@/components/SearchInput.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useSearch, valuesText } from '@/utils/search'

const props = defineProps({
  instance: { type: String, default: '' },
  // neighbor is the session (BGP info's peer row), or null when closed.
  neighbor: { type: Object, default: null },
})
const emit = defineEmits(['close'])

const tab = ref('fields')
const data = ref(null)
const error = ref('')
const loading = ref(false)
async function load() {
  if (!props.neighbor) return
  loading.value = true
  try {
    data.value = await api.agentBgpNeighbor(props.instance, props.neighbor.address)
    error.value = ''
  } catch (err) {
    error.value = errMsg(err)
  } finally {
    loading.value = false
  }
}
watch(
  () => props.neighbor,
  (n) => {
    data.value = null
    error.value = ''
    tab.value = 'fields'
    if (n) load()
  },
)

// flatten turns FRR's nested JSON into rows of a dotted name and a value.
function flatten(v, name, out) {
  if (v !== null && typeof v === 'object') {
    const keys = Object.keys(v)
    if (!keys.length) out.push({ name, value: Array.isArray(v) ? '[]' : '{}' })
    for (const k of keys) flatten(v[k], name ? `${name}.${k}` : k, out)
  } else {
    out.push({ name, value: String(v) })
  }
  return out
}
const rows = computed(() => (data.value?.detail ? flatten(data.value.detail, '', []) : []))
const search = useSearch(rows, (r) => valuesText(r.name, r.value))
const json = computed(() => (data.value?.detail ? JSON.stringify(data.value.detail, null, 2) : ''))
const columns = [
  { accessorKey: 'name', header: 'Field' },
  { accessorKey: 'value', header: 'Value' },
]
const tabs = [
  { label: 'Fields', value: 'fields', slot: 'fields' },
  { label: 'JSON', value: 'json', slot: 'json' },
]
const title = computed(() => {
  const n = props.neighbor
  if (!n) return ''
  return `Neighbour ${n.address}${n.description ? ` (${n.description})` : ''}`
})
</script>

<template>
  <UModal
    :open="!!neighbor"
    :title="title"
    :ui="{ content: 'sm:max-w-5xl' }"
    :dismissible="false"
    @update:open="(v) => !v && emit('close')"
  >
    <template #body>
      <div class="mb-2 flex justify-end">
        <UButton
          icon="i-lucide-refresh-cw"
          color="neutral"
          variant="outline"
          label="Refresh"
          :loading="loading"
          @click="load"
        />
      </div>
      <UAlert v-if="error" class="mb-2" color="error" variant="subtle" :title="error" />
      <UTabs v-model="tab" :items="tabs">
        <template #fields>
          <SearchInput v-model="search.search.value" class="mb-2" />
          <UTable
            :data="search.filtered.value"
            :columns="columns"
            :loading="loading && !data"
            :virtualize="{ estimateSize: 29 }"
            sticky
            class="h-[60vh]"
          >
            <template #name-cell="{ row }">
              <span class="font-mono text-xs">{{ row.original.name }}</span>
            </template>
            <template #value-cell="{ row }">
              <span class="font-mono text-xs">{{ row.original.value }}</span>
            </template>
            <template #empty>
              <div class="py-4 text-center text-muted">No information.</div>
            </template>
          </UTable>
        </template>
        <template #json>
          <pre class="h-[60vh] overflow-auto rounded bg-elevated p-2 font-mono text-xs">{{
            json
          }}</pre>
        </template>
      </UTabs>
    </template>
  </UModal>
</template>
