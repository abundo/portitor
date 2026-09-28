<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ServiceDialog: creates a custom service for useServiceDialog, from the
// "New service" entry of a port field's menu. Mounted once in AppLayout.
import { reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { customServices } from '@/api'
import { errMsg } from '@/api/http'
import { useServiceDialog } from '@/composables/useServiceDialog'
import { useObjectStore } from '@/stores/objects'

const { state, done } = useServiceDialog()
const objects = useObjectStore()
const toast = useToast()
const form = reactive({ name: '', ports: '', description: '' })
const saving = ref(false)

watch(
  () => state.open,
  (open) => open && Object.assign(form, { name: state.name, ports: '', description: '' }),
)

function onOpen(open) {
  if (!open) done(null)
}

async function save() {
  saving.value = true
  try {
    const svc = await customServices.create({ ...form })
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
  <UModal :open="state.open" title="New service" @update:open="onOpen">
    <template #body>
      <form id="service-form" class="space-y-3" @submit.prevent="save">
        <UFormField label="Name" required help="Lower case; port fields take it like ssh or https.">
          <UInput v-model="form.name" class="w-full" required placeholder="unifi" autofocus />
        </UFormField>
        <UFormField
          label="Ports"
          required
          help="A port (8443), a range (8000-8080) or several (8080, 8443, 10001). Built-in service names work too."
        >
          <UInput
            v-model="form.ports"
            class="w-full"
            :ui="{ base: 'font-mono' }"
            required
            placeholder="8080, 8443"
          />
        </UFormField>
        <UFormField label="Description">
          <UInput v-model="form.description" class="w-full" />
        </UFormField>
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
