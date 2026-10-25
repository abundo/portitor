<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import FirewallSwitcher from '@/components/FirewallSwitcher.vue'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()
const username = ref('')
const password = ref('')
const remember = ref(false)
const code = ref('')
// needCode: the user has two-factor login on; the server asked for a code.
const needCode = ref(false)
const error = ref('')
const busy = ref(false)

async function submit() {
  busy.value = true
  error.value = ''
  try {
    await auth.login(username.value, password.value, remember.value, code.value)
    const next =
      typeof route.query.next === 'string' && route.query.next.startsWith('/')
        ? route.query.next
        : '/'
    router.replace(next)
  } catch (err) {
    if (err.response?.data?.totp_required) {
      // The first ask is no error, only the code field showing.
      if (needCode.value) error.value = errMsg(err)
      needCode.value = true
      code.value = ''
      return
    }
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
        <FirewallSwitcher field />
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
        <UFormField
          v-if="needCode"
          label="Code"
          help="From your authenticator app, or one of your recovery codes."
        >
          <UInput v-model="code" class="w-full" autocomplete="one-time-code" autofocus required />
        </UFormField>
        <UCheckbox v-model="remember" label="Remember me for 30 days" />
        <UAlert v-if="error" color="error" variant="subtle" :title="error" />
        <UButton type="submit" block :loading="busy">Log in</UButton>
      </form>
    </UCard>
  </div>
</template>
