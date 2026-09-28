<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'

const toast = useToast()
const auth = useAuthStore()
const users = ref([])
const newUser = reactive({ username: '', password: '' })

async function load() {
  users.value = await api.users()
}
onMounted(load)

async function addUser() {
  try {
    await api.createUser(newUser.username, newUser.password)
    newUser.username = newUser.password = ''
    await load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

async function removeUser(u) {
  if (!window.confirm(`Delete user ${u.username}?`)) return
  try {
    await api.deleteUser(u.id)
    await load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <div class="grid gap-4 xl:grid-cols-2">
    <div class="card">
      <div class="mb-3 text-lg font-semibold">Users</div>
      <UTable
        :data="users"
        :columns="[
          { accessorKey: 'username', header: 'Username' },
          { id: 'actions', header: '' },
        ]"
      >
        <template #actions-cell="{ row }">
          <div class="flex justify-end">
            <UButton
              v-if="row.original.id !== auth.user?.id"
              size="xs"
              color="error"
              variant="ghost"
              icon="i-lucide-trash"
              @click="removeUser(row.original)"
            />
          </div>
        </template>
      </UTable>
      <form class="mt-3 flex flex-wrap items-end gap-2" @submit.prevent="addUser">
        <UFormField label="New user"
          ><UInput v-model="newUser.username" placeholder="username"
        /></UFormField>
        <UFormField label="Password"
          ><UInput v-model="newUser.password" type="password" autocomplete="new-password"
        /></UFormField>
        <UButton type="submit" icon="i-lucide-user-plus">Add</UButton>
      </form>
    </div>
  </div>
</template>
