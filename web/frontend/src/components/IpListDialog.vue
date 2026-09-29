<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// The form of an IP list. edit(row) opens it, edit() for a new one;
// `changed` follows a save or delete. The API key and password are
// write-only: the server never sends them back, and empty keeps them.
import { reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { ipLists } from '@/api'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useConfirm } from '@/composables/useConfirm'
import { useFormGuard } from '@/composables/useFormGuard'
import { inlineField, wideModal } from '@/utils/form'

const emit = defineEmits(['changed'])
const toast = useToast()
const auth = useAuthStore()
const { confirmDelete } = useConfirm()
const open = ref(false)
const saving = ref(false)
const form = reactive({})
const guard = useFormGuard(form, open)

const sources = [
  { label: 'CrowdSec Local API (as a bouncer)', value: 'crowdsec' },
  { label: 'URL: one address or prefix per line', value: 'url' },
]

function edit(src = {}) {
  Object.keys(form).forEach((k) => delete form[k])
  Object.assign(
    form,
    { name: '', description: '', source: 'crowdsec', url: '', username: '' },
    structuredClone(src),
  )
  open.value = true
}

async function save() {
  saving.value = true
  try {
    if (form.id) await ipLists.update(form.id, { ...form })
    else await ipLists.create({ ...form })
    open.value = false
    emit('changed')
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
  } finally {
    saving.value = false
  }
}

async function remove() {
  if (!(await confirmDelete(`IP list @${form.name}`))) return
  try {
    await ipLists.remove(form.id)
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
    :title="!auth.isAdmin ? 'IP list' : form.id ? 'Edit IP list' : 'New IP list'"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form id="iplist-form" @submit.prevent="save">
        <fieldset :disabled="!auth.isAdmin" class="space-y-3">
          <UFormField :ui="inlineField" label="Name" required help="Rules use it as @name.">
            <UInput v-model="form.name" class="w-full" placeholder="crowdsec" required />
          </UFormField>
          <UFormField :ui="inlineField" label="Description">
            <UInput v-model="form.description" class="w-full" />
          </UFormField>
          <UFormField :ui="inlineField" label="Source">
            <USelect v-model="form.source" :items="sources" class="w-full" />
          </UFormField>
          <UFormField
            :ui="inlineField"
            label="URL"
            required
            help="CrowdSec: the engine's Local API; it returns its ban decisions, community blocklists included. URL: plain text, one address or prefix per line, # and ; start comments. A CrowdSec blocklist integration (Console, Blocklists, Integrations), Spamhaus DROP and FireHOL lists work this way."
          >
            <UInput
              v-model="form.url"
              class="w-full"
              placeholder="http://127.0.0.1:8080 or https://…"
              required
            />
          </UFormField>
          <UFormField
            v-if="form.source === 'crowdsec'"
            :ui="inlineField"
            label="Bouncer API key"
            help="Stored on the server and never shown again. Leave empty to keep the stored key."
          >
            <UInput
              v-model="form.api_key"
              type="password"
              autocomplete="new-password"
              class="w-full"
              placeholder="from: cscli bouncers add portitor"
            />
          </UFormField>
          <template v-else>
            <UFormField :ui="inlineField" label="Username">
              <UInput
                v-model="form.username"
                class="w-full"
                placeholder="empty: no authentication"
              />
            </UFormField>
            <UFormField
              v-if="form.username"
              :ui="inlineField"
              label="Password"
              help="HTTP basic auth. Stored on the server and never shown again. Leave empty to keep the stored password."
            >
              <UInput
                v-model="form.password"
                type="password"
                autocomplete="new-password"
                class="w-full"
              />
            </UFormField>
          </template>
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
        <UButton v-if="auth.isAdmin" type="submit" form="iplist-form" :loading="saving"
          >Save</UButton
        >
      </div>
    </template>
  </UModal>
</template>
