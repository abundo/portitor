<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// The portal's firewalls and HA firewalls, as they answer now. Open loads a
// firewall's own GUI (/fw/<name>/; an HA firewall's from the host that is
// primary now); Edit its form, with Delete.
import { computed, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import DataGrid from '@/components/DataGrid.vue'
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import FirewallDialog from './FirewallDialog.vue'
import HADialog from './HADialog.vue'
import { portal } from './api'

const toast = useToast()
const rows = ref([])
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    rows.value = await portal.firewalls()
  } catch (e) {
    toast.add({ title: 'Could not list the firewalls', description: e.message, color: 'error' })
  } finally {
    loading.value = false
  }
}
const auto = useAutoRefresh(load, { seconds: 10 })

function stateText(r) {
  if (r.kind === 'ha') {
    if (!r.hosts?.length) return 'no hosts yet'
    if (r.hosts.length < 2) return `only the ${r.hosts[0].role}`
    const pair = r.connected ? 'paired' : 'not paired'
    return r.error ? `${pair}; ${r.active}: ${r.error}` : `${pair}; served by the ${r.active}`
  }
  return r.error || 'answers'
}

const columns = computed(() => [
  { field: 'name', headerName: 'Name', minWidth: 140 },
  {
    field: 'kind',
    headerName: 'Kind',
    maxWidth: 120,
    valueFormatter: (p) => (p.value === 'ha' ? 'HA pair' : 'Firewall'),
  },
  {
    colId: 'state',
    headerName: 'State',
    minWidth: 200,
    valueGetter: (p) => stateText(p.data),
    cellClassRules: {
      'text-error': (p) =>
        !!p.data.error || (p.data.kind === 'ha' && p.data.hosts?.length === 2 && !p.data.connected),
    },
  },
  { field: 'version', headerName: 'Version', maxWidth: 140 },
  { field: 'url', headerName: 'portitor-config', minWidth: 180 },
  { field: 'description', headerName: 'Description' },
])

const fwOpen = ref(false)
const haOpen = ref(false)
const editing = ref(null)

function edit(row) {
  editing.value = row
  if (row.kind === 'ha') haOpen.value = true
  else fwOpen.value = true
}
function addFirewall() {
  editing.value = null
  fwOpen.value = true
}
function addHA() {
  editing.value = null
  haOpen.value = true
}
async function saved() {
  await load()
  // An HA firewall's form shows its hosts: keep it on the fresh row.
  if (haOpen.value && editing.value)
    editing.value = rows.value.find((r) => r.name === editing.value.name) ?? null
}
async function created(name) {
  await load()
  const row = rows.value.find((r) => r.name === name)
  if (row) edit(row)
}

function openFirewall(row) {
  window.location.assign(row.path)
}
</script>

<template>
  <div class="card">
    <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <div class="text-lg font-semibold">Firewalls</div>
        <p class="max-w-3xl text-sm text-muted">
          Each firewall's GUI is its own portitor-config's, which keeps its configuration and its
          login. An HA pair is one firewall here, served by whichever host is primary now; its two
          hosts share one login.
        </p>
      </div>
      <div class="flex gap-2">
        <UButton icon="i-lucide-plus" @click="addFirewall">Add firewall</UButton>
        <UButton icon="i-lucide-plus" variant="outline" @click="addHA">Add HA firewall</UButton>
        <AutoRefreshButton :auto="auto" :loading="loading" />
      </div>
    </div>
    <DataGrid
      :rows="rows"
      :columns="columns"
      edit
      state-key="portal-firewalls"
      empty-text="No firewalls yet. Add one."
      :actions-width="80"
      @edit="edit"
    >
      <template #row-actions="{ row }">
        <UButton
          size="sm"
          variant="soft"
          icon="i-lucide-external-link"
          :disabled="!!row.error"
          :title="`Open ${row.name}'s GUI`"
          aria-label="Open"
          @click="openFirewall(row)"
        />
      </template>
    </DataGrid>
  </div>
  <FirewallDialog v-model:open="fwOpen" :row="editing" @saved="saved" />
  <HADialog v-model:open="haOpen" :row="editing" @saved="saved" @created="created" />
</template>
