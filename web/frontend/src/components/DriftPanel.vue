<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// DriftPanel: a firewall with portitor-config, its virtual firewalls here
// and there. One changed there (break-glass) is settled by taking that
// version here or overwriting it; the next commit pushes the rest.
import { onMounted, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import SearchInput from '@/components/SearchInput.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useConfirm } from '@/composables/useConfirm'
import { useSearch } from '@/utils/search'

const props = defineProps({ firewall: { type: Object, required: true } })
const toast = useToast()
const { ask } = useConfirm()
const rows = ref([])
const error = ref('')
const busy = ref('')
const { search, filtered } = useSearch(rows, (r) => `${r.name} ${r.state}`)

const color = {
  same: 'success',
  'changed here': 'info',
  'not pushed yet': 'info',
  'deleted here': 'info',
  'changed there': 'warning',
  'name taken there': 'error',
  "the firewall's": 'neutral',
}

async function load() {
  try {
    rows.value = await api.drift(props.firewall.id)
    error.value = ''
  } catch (err) {
    error.value = errMsg(err)
  }
}
onMounted(load)

async function settle(row, action) {
  const message =
    action === 'take'
      ? `Take ${props.firewall.name}'s version of ${row.name}? It replaces this one here.`
      : `Overwrite ${row.name} on ${props.firewall.name} with this version? The changes made there are lost.`
  if (!(await ask({ title: action === 'take' ? 'Take' : 'Overwrite', message }))) return
  busy.value = row.name
  try {
    await api.settleDrift(props.firewall.id, row.name, action)
    toast.add({
      title: action === 'take' ? `Took ${row.name}` : `Overwrote ${row.name}`,
      color: 'success',
    })
    await load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    busy.value = ''
  }
}
</script>

<template>
  <div class="card">
    <div class="mb-2 flex items-center gap-2">
      <div class="font-semibold">
        {{ firewall.name }}: virtual firewalls here and on its portitor-config
      </div>
      <UButton icon="i-lucide-refresh-cw" variant="ghost" size="xs" label="Refresh" @click="load" />
    </div>
    <div class="mb-2">
      <SearchInput v-model="search" />
    </div>
    <UAlert v-if="error" color="error" variant="subtle" :title="error" class="mb-2" />
    <UTable
      :data="filtered"
      :columns="[
        { accessorKey: 'name', header: 'Virtual firewall' },
        { id: 'state', header: 'State' },
        { id: 'actions', header: '' },
      ]"
    >
      <template #state-cell="{ row }">
        <UBadge
          :color="color[row.original.state] ?? 'neutral'"
          variant="subtle"
          :label="row.original.state"
        />
      </template>
      <template #actions-cell="{ row }">
        <div v-if="row.original.state === 'changed there'" class="flex gap-1">
          <UButton
            size="xs"
            variant="outline"
            label="Take"
            :loading="busy === row.original.name"
            @click="settle(row.original, 'take')"
          />
          <UButton
            size="xs"
            variant="outline"
            color="warning"
            label="Overwrite"
            :loading="busy === row.original.name"
            @click="settle(row.original, 'overwrite')"
          />
        </div>
      </template>
      <template #empty>No virtual firewalls on {{ firewall.name }}.</template>
    </UTable>
  </div>
</template>
