<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- The prefixes of one BGP neighbour as FRR has them: received (before
     the inbound policy), filtered (denied by it) and advertised, in IPv4
     and IPv6 unicast. Read-only; the lists can be a full table, so the
     tables scroll virtually. -->
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

const tab = ref('received')
const data = ref(null)
const error = ref('')
const loading = ref(false)
async function load() {
  if (!props.neighbor) return
  loading.value = true
  try {
    data.value = await api.agentBgpRoutes(props.instance, props.neighbor.address)
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
    tab.value = 'received'
    if (n) load()
  },
)

const lists = {
  received: computed(() => data.value?.received ?? []),
  filtered: computed(() => data.value?.filtered ?? []),
  advertised: computed(() => data.value?.advertised ?? []),
}
const text = (r) => valuesText(r.prefix, r.next_hop, r.path, r.origin)
const searches = {
  received: useSearch(lists.received, text),
  filtered: useSearch(lists.filtered, text),
  advertised: useSearch(lists.advertised, text),
}
const tabs = computed(() =>
  [
    { label: 'Received', value: 'received' },
    { label: 'Filtered', value: 'filtered' },
    { label: 'Advertised', value: 'advertised' },
  ].map((t) => ({
    ...t,
    slot: 'list',
    badge: data.value ? lists[t.value].value.length : undefined,
  })),
)
const noSoftReconfig = computed(() => tab.value === 'filtered' && !!data.value?.received_accepted)
const columns = [
  { accessorKey: 'prefix', header: 'Prefix' },
  { accessorKey: 'next_hop', header: 'Next hop' },
  { accessorKey: 'metric', header: 'MED' },
  { accessorKey: 'local_pref', header: 'Local pref' },
  { accessorKey: 'weight', header: 'Weight' },
  { accessorKey: 'path', header: 'AS path' },
  { accessorKey: 'origin', header: 'Origin' },
]
const title = computed(() => {
  const n = props.neighbor
  if (!n) return ''
  return `Prefixes of neighbour ${n.address}${n.description ? ` (${n.description})` : ''}`
})
</script>

<template>
  <UModal
    :open="!!neighbor"
    :title="title"
    :ui="{ content: 'sm:max-w-6xl' }"
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
      <UAlert
        v-for="note in data?.notes ?? []"
        :key="note"
        class="mb-2"
        color="warning"
        variant="subtle"
        :title="note"
      />
      <UTabs v-model="tab" :items="tabs">
        <template #list>
          <SearchInput v-model="searches[tab].search.value" class="mb-2" />
          <div
            v-if="noSoftReconfig"
            class="flex h-[60vh] items-center justify-center p-4 text-center text-muted"
          >
            Soft reconfiguration inbound is not enabled on this neighbour, so FRR does not keep the
            routes the inbound policy filtered. Turn it on (Soft reconfiguration in the neighbour's
            address family) to see them.
          </div>
          <UTable
            v-else
            :data="searches[tab].filtered.value"
            :columns="columns"
            :loading="loading && !data"
            :virtualize="{ estimateSize: 29 }"
            sticky
            class="h-[60vh]"
          >
            <template #prefix-cell="{ row }">
              <span class="font-mono text-xs">{{ row.original.prefix }}</span>
            </template>
            <template #next_hop-cell="{ row }">
              <span class="font-mono text-xs">{{ row.original.next_hop }}</span>
            </template>
            <template #path-cell="{ row }">
              <span class="font-mono text-xs">{{ row.original.path }}</span>
            </template>
            <template #empty>
              <div class="py-4 text-center text-muted">No prefixes.</div>
            </template>
          </UTable>
        </template>
      </UTabs>
    </template>
  </UModal>
</template>
