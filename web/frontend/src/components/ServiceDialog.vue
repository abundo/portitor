<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ServiceDialog: creates a custom service for useServiceDialog, from the
// "New service" entry of a rule's Service cell. Mounted once in AppLayout.
import { ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import ServiceOptions from '@/components/ServiceOptions.vue'
import { customServices } from '@/api'
import { errMsg } from '@/api/http'
import { useServiceDialog } from '@/composables/useServiceDialog'
import { useObjectStore } from '@/stores/objects'
import { newService } from '@/utils/services'
import { inlineField, wideModal } from '@/utils/form'

const { state, done } = useServiceDialog()
const objects = useObjectStore()
const toast = useToast()
const form = ref(newService())
const saving = ref(false)

watch(
  () => state.open,
  (open) => open && (form.value = newService(state.name)),
)

function onOpen(open) {
  if (!open) done(null)
}

async function save() {
  saving.value = true
  try {
    const svc = await customServices.create(form.value)
    await objects.load(true).catch(() => {})
    done(svc)
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <UModal :open="state.open" title="New service" :ui="wideModal" @update:open="onOpen">
    <template #body>
      <form id="service-form" class="space-y-3" @submit.prevent="save">
        <UFormField
          :ui="inlineField"
          label="Name"
          required
          help="Lower case; a rule's Service cell takes it like ssh or ping."
        >
          <UInput v-model="form.name" class="w-full" required placeholder="unifi" autofocus />
        </UFormField>
        <UFormField :ui="inlineField" label="Description">
          <UInput v-model="form.description" class="w-full" />
        </UFormField>
        <ServiceOptions v-model="form" />
      </form>
    </template>
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton color="neutral" variant="ghost" @click="done(null)">Cancel</UButton>
        <UButton type="submit" form="service-form" :loading="saving">Save</UButton>
      </div>
    </template>
  </UModal>
</template>
