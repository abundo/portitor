<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// The HA pairs this portal is the third vote of: their witness strings
// (portitor-config witness-string on the primary). Pairing an HA firewall's
// hosts adds its string here when the portal is to be its witness.
import { reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import DataGrid from '@/components/DataGrid.vue'
import { useFormGuard } from '@/composables/useFormGuard'
import { useConfirm } from '@/composables/useConfirm'
import { inlineField, wideModal } from '@/utils/form'
import { portal } from './api'

const toast = useToast()
const { confirmDelete } = useConfirm()
const rows = ref([])

async function load() {
  try {
    rows.value = (await portal.witnesses()).map((w) => ({
      ...w,
      hosts_text: (w.hosts ?? []).join(', '),
    }))
  } catch (e) {
    toast.add({
      title: 'Could not list the witness strings',
      description: e.message,
      color: 'error',
    })
  }
}
load()

const columns = [
  { field: 'pair', headerName: 'Pair', maxWidth: 220 },
  { field: 'hosts_text', headerName: 'Hosts' },
]

const open = ref(false)
const editing = ref(null)
const form = reactive({ string: '' })
const guard = useFormGuard(form, open)
watch(open, (o) => o && (form.string = ''))

function add() {
  editing.value = null
  open.value = true
}
function edit(row) {
  editing.value = row
  open.value = true
}

async function save() {
  try {
    await portal.addWitness(form.string.trim())
    open.value = false
    load()
  } catch (e) {
    toast.add({ title: 'Not added', description: e.message, color: 'error' })
  }
}

async function remove() {
  if (
    !(await confirmDelete(
      `the witness of ${editing.value.pair}`,
      'The pair loses its third vote here.',
    ))
  )
    return
  try {
    await portal.deleteWitness(editing.value.pair)
    open.value = false
    load()
  } catch (e) {
    toast.add({ title: 'Not deleted', description: e.message, color: 'error' })
  }
}
</script>

<template>
  <div class="card">
    <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <div class="text-lg font-semibold">HA witness</div>
        <p class="max-w-3xl text-sm text-muted">
          The HA pairs this portal is the third vote of. Pairing an HA firewall's hosts adds its
          pair here; a pair made elsewhere is added by its witness string (<span class="font-mono"
            >portitor-config witness-string</span
          >
          on the primary).
        </p>
      </div>
      <UButton icon="i-lucide-plus" @click="add">Add witness string</UButton>
    </div>
    <DataGrid
      :rows="rows"
      :columns="columns"
      edit
      :view-only="() => true"
      state-key="portal-witness"
      :row-id="(r) => r.pair"
      empty-text="None."
      @edit="edit"
    />
  </div>
  <UModal
    :open="open"
    :title="editing ? `Witness of ${editing.pair}` : 'Add witness string'"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form v-if="!editing" id="witness-form" class="space-y-3" @submit.prevent="save">
        <UFormField :ui="inlineField" label="Witness string" required>
          <UTextarea
            v-model="form.string"
            :rows="3"
            class="w-full font-mono"
            placeholder="portitor-witness:..."
          />
        </UFormField>
      </form>
      <div v-else class="space-y-1 text-sm">
        <div v-for="h in editing.hosts" :key="h" class="font-mono">{{ h }}</div>
      </div>
    </template>
    <template #footer>
      <div class="flex w-full items-center gap-2">
        <UButton
          v-if="editing"
          color="error"
          variant="outline"
          icon="i-lucide-trash-2"
          @click="remove"
        >
          Delete
        </UButton>
        <div class="ml-auto flex gap-2">
          <UButton color="neutral" variant="ghost" @click="guard.close">{{
            editing ? 'Close' : 'Cancel'
          }}</UButton>
          <UButton v-if="!editing" type="submit" form="witness-form">Add</UButton>
        </div>
      </div>
    </template>
  </UModal>
</template>
