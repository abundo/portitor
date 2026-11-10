<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, reactive } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useDeployStore } from '@/stores/deploy'
import { usePageForm } from '@/composables/useFormGuard'
import FormHeader from '@/components/FormHeader.vue'

// The firewall's options, every virtual firewall's: settings leaves saved
// alone (PUT /api/settings takes the fields it is given).
const toast = useToast()
const deploy = useDeployStore()
const options = reactive({
  drop_ip_options_input: false,
  drop_ip_options_forward: false,
})
const form = usePageForm(options)

async function load() {
  const s = await api.settings()
  for (const k of Object.keys(options)) options[k] = !!s[k]
  form.mark()
}
onMounted(load)

async function save() {
  try {
    const s = await api.saveSettings({ ...options })
    for (const k of Object.keys(options)) options[k] = !!s[k]
    form.mark()
    toast.add({ title: 'Options saved', color: 'success' })
    deploy.refresh()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <form class="grid gap-4 xl:grid-cols-2" @submit.prevent="save">
    <FormHeader title="Options" class="xl:col-span-2">
      <UButton type="submit">Save</UButton>
    </FormHeader>
    <div class="card">
      <div class="mb-1 text-lg font-semibold">IP options</div>
      <p class="mb-4 text-sm text-muted">
        IPv4 packets with IP options (Record Route, Timestamp, Router Alert, ...: a header longer
        than 20 bytes). Normal traffic carries none, and they have been the way in for kernel flaws.
        Dropped first in the chain, before the rules and established connections, in every virtual
        firewall; the Rules page shows what each drop counted. Source-routed packets are always
        dropped. Takes effect on the next commit.
      </p>
      <div class="space-y-3">
        <UFormField
          label="Drop packets with options to the firewall"
          help="In the input chain. IGMP's reports (Router Alert) still come in."
        >
          <USwitch v-model="options.drop_ip_options_input" />
        </UFormField>
        <UFormField
          label="Drop packets with options when forwarding"
          help="In the forward chain: to and from the hosts behind the firewall."
        >
          <USwitch v-model="options.drop_ip_options_forward" />
        </UFormField>
      </div>
    </div>
  </form>
</template>
