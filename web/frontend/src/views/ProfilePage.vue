<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { reactive } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { usePageForm } from '@/composables/useFormGuard'
import { dateFormat, datetime } from '@/utils/time'

const toast = useToast()
const auth = useAuthStore()
const form = reactive({
  full_name: auth.user?.full_name ?? '',
  email: auth.user?.email ?? '',
})

const profileForm = usePageForm(form)
profileForm.mark()

const now = new Date()
const dateFormats = [
  {
    value: 'locale',
    label: `Browser language (${now.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' })})`,
  },
  { value: 'iso', label: 'YYYY-MM-DD HH:MM:SS' },
]

async function save() {
  try {
    await auth.updateProfile({ ...form })
    profileForm.mark()
    toast.add({ title: 'Profile saved', color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <div class="max-w-xl space-y-4">
    <div class="card">
      <div class="mb-3 text-lg font-semibold">My settings</div>
      <form class="space-y-3" @submit.prevent="save">
        <UFormField label="Username" help="Used to log in.">
          <UInput
            :model-value="auth.user?.username"
            class="w-full"
            autocomplete="username"
            disabled
          />
        </UFormField>
        <UFormField label="Full name">
          <UInput v-model="form.full_name" class="w-full" autocomplete="name" />
        </UFormField>
        <UFormField label="Email">
          <UInput v-model="form.email" type="email" class="w-full" autocomplete="email" />
        </UFormField>
        <div class="flex items-center gap-3">
          <UButton type="submit">Save</UButton>
          <UButton to="/profile/password" color="neutral" variant="ghost" icon="i-lucide-key-round">
            Change password
          </UButton>
        </div>
      </form>
    </div>
    <div class="card">
      <div class="mb-3 text-lg font-semibold">Display</div>
      <UFormField
        label="Date and time format"
        :help="`Remembered in this browser. Now: ${datetime(now)}`"
      >
        <USelect v-model="dateFormat" :items="dateFormats" class="w-full" />
      </UFormField>
    </div>
  </div>
</template>
