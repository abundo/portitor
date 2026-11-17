<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// The portal's login: its own users. Each firewall has its own login too
// (an HA firewall's two hosts share one).
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { portal } from './api'

const router = useRouter()
const username = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)
const version = ref('')

onMounted(async () => {
  try {
    const v = (await portal.version()).version ?? ''
    version.value = /^\d/.test(v) ? `v${v}` : v
  } catch {
    // cosmetic
  }
})

async function submit() {
  busy.value = true
  error.value = ''
  try {
    await portal.login(username.value, password.value)
    password.value = ''
    router.replace({ name: 'firewalls' })
  } catch (err) {
    error.value = err.message || 'Login failed'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-muted p-4">
    <UCard class="w-full max-w-sm">
      <template #header>
        <div class="flex items-center gap-2 text-lg font-semibold">
          <UIcon name="i-lucide-shield" class="size-6 text-primary" /> Portitor
          <span v-if="version" class="ml-auto font-mono text-xs font-normal text-muted">
            {{ version }}
          </span>
        </div>
      </template>
      <form class="space-y-4" @submit.prevent="submit">
        <p class="text-sm text-muted">
          Log in to portitor-manager. Each firewall has its own login too.
        </p>
        <UFormField label="Username">
          <UInput v-model="username" class="w-full" autocomplete="username" autofocus required />
        </UFormField>
        <UFormField label="Password">
          <UInput
            v-model="password"
            type="password"
            class="w-full"
            autocomplete="current-password"
            required
          />
        </UFormField>
        <UAlert v-if="error" color="error" variant="subtle" :title="error" />
        <UButton type="submit" block :loading="busy">Log in</UButton>
      </form>
    </UCard>
  </div>
</template>
