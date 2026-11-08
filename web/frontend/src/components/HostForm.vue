<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// The form of a named host or prefix (address_objects). edit(row) shows it beside the tree,
// edit() for a new one; `changed` follows a save or delete.
import TagsInput from '@/components/TagsInput.vue'
import { computed, reactive, ref, toRaw } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { hosts as addressObjects } from '@/api/config'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useConfirm } from '@/composables/useConfirm'
import { useFormGuard } from '@/composables/useFormGuard'
import { inlineField } from '@/utils/form'
import FormPane from '@/components/FormPane.vue'
import { folderOptions } from '@/utils/folders'

// folders: every folder (object_folders), for the Folder field.
const props = defineProps({ folders: { type: Array, default: () => [] } })
const emit = defineEmits(['changed'])
const toast = useToast()
const auth = useAuthStore()
const { confirmDelete } = useConfirm()
const open = ref(false)
const saving = ref(false)
const form = reactive({})
const guard = useFormGuard(form, open)
const folderItems = computed(() => folderOptions(props.folders, 'hosts'))

function edit(src = {}) {
  Object.keys(form).forEach((k) => delete form[k])
  Object.assign(form, { name: '', addresses: [], description: '' }, structuredClone(toRaw(src)))
  form.folder_id ??= 0
  open.value = true
}

async function save() {
  saving.value = true
  try {
    if (form.id) await addressObjects.update(form.id, { ...form })
    else await addressObjects.create({ ...form })
    open.value = false
    emit('changed')
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
  } finally {
    saving.value = false
  }
}

async function remove() {
  if (!(await confirmDelete(`host ${form.name}`))) return
  try {
    await addressObjects.remove(form.id)
    open.value = false
    emit('changed')
  } catch (err) {
    toast.add({ title: errMsg(err, 'Delete failed'), color: 'error' })
  }
}

// hide closes the form without asking (the page asked already).
const hide = () => (open.value = false)

defineExpose({ edit, hide, open })
</script>

<template>
  <FormPane v-if="open" :title="!auth.isAdmin ? 'Host' : form.id ? 'Edit host' : 'New host'">
    <template #actions>
      <UButton
        v-if="form.id && auth.isAdmin"
        color="error"
        variant="ghost"
        icon="i-lucide-trash"
        label="Delete"
        @click="remove"
      />
      <UButton v-if="auth.isAdmin" color="neutral" variant="ghost" @click="guard.close"
        >Cancel</UButton
      >
      <UButton v-if="auth.isAdmin" type="submit" form="host-form" :loading="saving">Save</UButton>
    </template>
    <form id="host-form" @submit.prevent="save">
      <fieldset :disabled="!auth.isAdmin" class="space-y-3">
        <UFormField :ui="inlineField" label="Name" required>
          <UInput v-model="form.name" class="w-full" placeholder="nas" required />
        </UFormField>
        <UFormField
          :ui="inlineField"
          label="Addresses and prefixes"
          help="Give a host both its IPv4 and IPv6 address: a rule using it then covers both."
        >
          <TagsInput v-model="form.addresses" placeholder="192.168.1.10, fd00:1::10" />
        </UFormField>
        <UFormField :ui="inlineField" label="Description">
          <UInput v-model="form.description" class="w-full" />
        </UFormField>
        <UFormField :ui="inlineField" label="Folder">
          <USelect v-model="form.folder_id" :items="folderItems" class="w-full" />
        </UFormField>
      </fieldset>
    </form>
  </FormPane>
</template>
