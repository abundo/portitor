<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// FirewallSwitcher: behind portitor-web, which serves each firewall's own
// GUI at /fw/<name>/, a pick of its firewalls; each has its own login, but
// for the two hosts of an HA pair, which share one. field: as a form field
// (the login page), else in the top bar.
import { computed, onMounted, ref } from 'vue'
import { BASE, portal } from '@/utils/base'
import { confirmDiscard } from '@/composables/useFormGuard'

defineProps({ field: { type: Boolean, default: false } })

const firewalls = ref([])
const here = BASE.split('/')[2] ?? ''

onMounted(async () => {
  if (!portal) return
  try {
    const res = await fetch('/portal/v1/firewalls', { credentials: 'same-origin' })
    if (res.ok) firewalls.value = await res.json()
  } catch {
    // only the switch is missing then
  }
})

const items = computed(() =>
  firewalls.value.map((f) => ({
    label: f.error ? `${f.name} (${f.error})` : f.name,
    value: f.name,
    disabled: !!f.error && f.name !== here,
  })),
)
const current = computed({
  get: () => here,
  set: async (name) => {
    if (name === here || !(await confirmDiscard())) return
    window.location.assign(`/fw/${name}/`)
  },
})
</script>

<template>
  <template v-if="portal && firewalls.length > 1">
    <UFormField v-if="field" label="Firewall">
      <USelect v-model="current" :items="items" class="w-full" />
    </UFormField>
    <div v-else class="ml-2 flex items-center gap-2">
      <span class="hidden text-sm text-muted md:inline">Firewall</span>
      <USelect v-model="current" :items="items" class="w-40" />
    </div>
  </template>
</template>
