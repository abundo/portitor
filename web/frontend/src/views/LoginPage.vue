<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()
const username = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  busy.value = true
  error.value = ''
  try {
    await auth.login(username.value, password.value)
    const next =
      typeof route.query.next === 'string' && route.query.next.startsWith('/')
        ? route.query.next
        : '/'
    router.replace(next)
  } catch (err) {
    error.value = errMsg(err, 'Login failed')
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
        </div>
      </template>
      <form class="space-y-4" @submit.prevent="submit">
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
