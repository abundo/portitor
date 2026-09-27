<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'

const toast = useToast()
const auth = useAuthStore()
const deploy = useDeployStore()
const settings = reactive({
  agent_url: '',
  agent_token: '',
  agent_fingerprint: '',
  confirm_timeout: 120,
  wg_endpoint_host: '',
})
const hasToken = ref(false)
const users = ref([])
const newUser = reactive({ username: '', password: '' })
const pw = reactive({ current: '', next: '' })
const version = ref(null)

async function load() {
  const s = await api.settings()
  Object.assign(settings, s, { agent_token: '' })
  hasToken.value = s.has_agent_token
  users.value = await api.users()
  version.value = await api.version()
}
onMounted(load)

async function saveSettings() {
  try {
    const s = await api.saveSettings({
      ...settings,
      confirm_timeout: Number(settings.confirm_timeout),
    })
    hasToken.value = s.has_agent_token
    settings.agent_token = ''
    toast.add({ title: 'Settings saved', color: 'success' })
    deploy.refresh()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

async function addUser() {
  try {
    await api.createUser(newUser.username, newUser.password)
    newUser.username = newUser.password = ''
    users.value = await api.users()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

async function removeUser(u) {
  if (!window.confirm(`Delete user ${u.username}?`)) return
  try {
    await api.deleteUser(u.id)
    users.value = await api.users()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

async function changePassword() {
  try {
    await api.changePassword(pw.current, pw.next)
    pw.current = pw.next = ''
    toast.add({ title: 'Password changed; other sessions are logged out', color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <div class="grid gap-4 xl:grid-cols-2">
    <div class="card">
      <div class="mb-1 text-lg font-semibold">Portitor agent</div>
      <p class="mb-4 text-sm text-muted">
        Run <code class="font-mono">portitor-agent init --host &lt;address&gt;</code> on the
        firewall; it prints the token and the certificate fingerprint.
      </p>
      <form class="space-y-3" @submit.prevent="saveSettings">
        <UFormField label="Agent URL"
          ><UInput
            v-model="settings.agent_url"
            class="w-full font-mono"
            placeholder="https://192.168.1.1:8443"
        /></UFormField>
        <UFormField
          label="Token"
          :help="hasToken ? 'A token is stored. Leave empty to keep it.' : 'Not set.'"
        >
          <UInput
            v-model="settings.agent_token"
            type="password"
            class="w-full font-mono"
            autocomplete="off"
          />
        </UFormField>
        <UFormField
          label="Certificate fingerprint (SHA-256)"
          help="Pins the agent's self-signed certificate. Empty: verify against system CAs."
        >
          <UInput v-model="settings.agent_fingerprint" class="w-full font-mono text-xs" />
        </UFormField>
        <UFormField
          label="Default auto-rollback (seconds)"
          help="After an apply, the agent restores the previous configuration unless you confirm within this time. 0 disables it."
        >
          <UInput v-model="settings.confirm_timeout" type="number" class="w-40" />
        </UFormField>
        <UFormField
          label="Public WireGuard endpoint host"
          help="Name or address clients connect to; used in generated client configs."
        >
          <UInput
            v-model="settings.wg_endpoint_host"
            class="w-full font-mono"
            placeholder="home.example.org"
          />
        </UFormField>
        <div class="flex items-center gap-3">
          <UButton type="submit">Save</UButton>
          <UBadge v-if="deploy.error" color="error" variant="subtle" :label="deploy.error" />
          <UBadge
            v-else-if="deploy.status"
            color="success"
            variant="subtle"
            :label="`connected to ${deploy.status.hostname}`"
          />
        </div>
      </form>
    </div>

    <div class="space-y-4">
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

      <div class="card">
        <div class="mb-3 text-lg font-semibold">Change my password</div>
        <form class="flex flex-wrap items-end gap-2" @submit.prevent="changePassword">
          <UFormField label="Current"
            ><UInput v-model="pw.current" type="password" autocomplete="current-password"
          /></UFormField>
          <UFormField label="New (10+ characters)"
            ><UInput v-model="pw.next" type="password" autocomplete="new-password"
          /></UFormField>
          <UButton type="submit">Change</UButton>
        </form>
      </div>
      <p v-if="version" class="text-xs text-muted">
        portitor-web {{ version.version }} ({{ version.commit.slice(0, 8) }}),
        {{ version.go_version }}
      </p>
    </div>
  </div>
</template>
