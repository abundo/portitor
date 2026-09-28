<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { reactive } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'

const toast = useToast()
const auth = useAuthStore()
const form = reactive({
  username: auth.user?.username ?? '',
  full_name: auth.user?.full_name ?? '',
  email: auth.user?.email ?? '',
})

async function save() {
  try {
    await auth.updateProfile({ ...form })
    toast.add({ title: 'Profile saved', color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <div class="card max-w-xl">
    <div class="mb-3 text-lg font-semibold">My settings</div>
    <form class="space-y-3" @submit.prevent="save">
      <UFormField label="Username" help="Used to log in.">
        <UInput v-model="form.username" class="w-full" autocomplete="username" />
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
</template>
