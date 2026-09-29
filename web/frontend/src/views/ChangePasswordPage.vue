<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { reactive } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { usePageForm } from '@/composables/useFormGuard'

const toast = useToast()
const pw = reactive({ current: '', next: '', repeat: '' })
// Empty is saved: anything typed is unsaved until the password changes.
usePageForm(pw).mark()

async function changePassword() {
  if (pw.next !== pw.repeat) {
    toast.add({ title: 'The new passwords do not match', color: 'error' })
    return
  }
  try {
    await api.changePassword(pw.current, pw.next)
    pw.current = pw.next = pw.repeat = ''
    toast.add({ title: 'Password changed; other sessions are logged out', color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <div class="card max-w-xl">
    <div class="mb-1 text-lg font-semibold">Change password</div>
    <p class="mb-4 text-sm text-muted">Your other sessions are logged out.</p>
    <form class="space-y-3" @submit.prevent="changePassword">
      <UFormField label="Current password">
        <UInput
          v-model="pw.current"
          type="password"
          class="w-full"
          autocomplete="current-password"
        />
      </UFormField>
      <UFormField label="New password" help="At least 10 characters.">
        <UInput v-model="pw.next" type="password" class="w-full" autocomplete="new-password" />
      </UFormField>
      <UFormField label="Repeat new password">
        <UInput v-model="pw.repeat" type="password" class="w-full" autocomplete="new-password" />
      </UFormField>
      <UButton type="submit">Change password</UButton>
    </form>
  </div>
</template>
