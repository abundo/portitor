<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// The form of a folder of hosts or IP lists (object_folders). edit(row)
// opens it, edit({ kind, parent_id }) for a new one; `changed` follows a
// save or delete. Only an empty folder can be deleted.
import { computed, reactive, ref, toRaw } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { objectFolders } from '@/api'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useConfirm } from '@/composables/useConfirm'
import { useFormGuard } from '@/composables/useFormGuard'
import { inlineField, wideModal } from '@/utils/form'
import { folderOptions } from '@/utils/folders'

const props = defineProps({ folders: { type: Array, required: true } })
const emit = defineEmits(['changed'])
const toast = useToast()
const auth = useAuthStore()
const { confirmDelete } = useConfirm()
const open = ref(false)
const saving = ref(false)
const form = reactive({})
const guard = useFormGuard(form, open)

const parents = computed(() => folderOptions(props.folders, form.kind, form.id ?? null))

function edit(src) {
  Object.keys(form).forEach((k) => delete form[k])
  Object.assign(form, { name: '' }, structuredClone(toRaw(src)))
  form.parent_id ??= 0
  open.value = true
}

async function save() {
  saving.value = true
  try {
    if (form.id) await objectFolders.update(form.id, { ...form })
    else await objectFolders.create({ ...form })
    open.value = false
    emit('changed')
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
  } finally {
    saving.value = false
  }
}

async function remove() {
  if (!(await confirmDelete(`folder ${form.name}`, 'Only an empty folder can be deleted.'))) return
  try {
    await objectFolders.remove(form.id)
    open.value = false
    emit('changed')
  } catch (err) {
    toast.add({ title: errMsg(err, 'Delete failed'), color: 'error' })
  }
}

defineExpose({ edit })
</script>

<template>
  <UModal
    :open="open"
    :title="!auth.isAdmin ? 'Folder' : form.id ? 'Edit folder' : 'New folder'"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form id="folder-form" @submit.prevent="save">
        <fieldset :disabled="!auth.isAdmin" class="space-y-3">
          <UFormField :ui="inlineField" label="Name" required>
            <UInput v-model="form.name" class="w-full" placeholder="Servers" required />
          </UFormField>
          <UFormField :ui="inlineField" label="Inside">
            <USelect v-model="form.parent_id" :items="parents" class="w-full" />
          </UFormField>
        </fieldset>
      </form>
    </template>
    <template #footer>
      <div class="flex w-full gap-2">
        <UButton
          v-if="form.id && auth.isAdmin"
          color="error"
          variant="ghost"
          icon="i-lucide-trash"
          label="Delete"
          @click="remove"
        />
        <UButton class="ms-auto" color="neutral" variant="ghost" @click="guard.close">{{
          auth.isAdmin ? 'Cancel' : 'Close'
        }}</UButton>
        <UButton v-if="auth.isAdmin" type="submit" form="folder-form" :loading="saving"
          >Save</UButton
        >
      </div>
    </template>
  </UModal>
</template>
