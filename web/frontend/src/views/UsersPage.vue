<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useConfirm } from '@/composables/useConfirm'
import { useFormGuard } from '@/composables/useFormGuard'
import { inlineField, wideModal } from '@/utils/form'

const toast = useToast()
const auth = useAuthStore()
const { confirmDelete } = useConfirm()
const users = ref([])
const roles = [
  { label: 'Admin', value: 'admin', description: 'Changes and deploys everything' },
  { label: 'Viewer', value: 'viewer', description: 'Reads the configuration and status' },
]
const roleLabel = (role) => roles.find((r) => r.value === role)?.label ?? role

async function load() {
  users.value = await api.users()
}
onMounted(load)

// The dialog adds a user, or changes an existing user's role (not your own).
const open = ref(false)
const saving = ref(false)
const editing = ref(null)
const form = reactive({ username: '', password: '', role: 'viewer' })
const guard = useFormGuard(form, open)
const isSelf = computed(() => editing.value?.id === auth.user?.id)

function openCreate() {
  editing.value = null
  Object.assign(form, { username: '', password: '', role: 'viewer' })
  open.value = true
}

function openEdit(u) {
  editing.value = u
  Object.assign(form, { username: u.username, password: '', role: u.role })
  open.value = true
}

async function save() {
  saving.value = true
  try {
    if (!editing.value) await api.createUser(form.username, form.password, form.role)
    else if (!isSelf.value && form.role !== editing.value.role)
      await api.setUserRole(editing.value.id, form.role)
    open.value = false
    await load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}

// The password dialog sets another user's password (your own is changed
// under Change password, which asks for the current one).
const pwOpen = ref(false)
const pwSaving = ref(false)
const pw = reactive({ next: '', repeat: '' })
const pwGuard = useFormGuard(pw, pwOpen)
const pwMismatch = computed(() => pw.repeat !== '' && pw.next !== pw.repeat)

function openPassword() {
  Object.assign(pw, { next: '', repeat: '' })
  pwOpen.value = true
}

async function savePassword() {
  if (pw.next !== pw.repeat) {
    toast.add({ title: 'The passwords do not match', color: 'error' })
    return
  }
  pwSaving.value = true
  try {
    await api.setUserPassword(editing.value.id, pw.next)
    pwOpen.value = false
    toast.add({
      title: `Password set for ${editing.value.username}; their sessions are logged out`,
      color: 'success',
    })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    pwSaving.value = false
  }
}

async function remove() {
  if (!(await confirmDelete(`user ${editing.value.username}`))) return
  try {
    await api.deleteUser(editing.value.id)
    open.value = false
    await load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <div class="grid gap-4 xl:grid-cols-2">
    <div class="card">
      <div class="mb-3 flex items-center justify-between gap-3">
        <div class="text-lg font-semibold">Users</div>
        <UButton icon="i-lucide-user-plus" label="Add" @click="openCreate" />
      </div>
      <UTable
        :data="users"
        :columns="[
          { id: 'actions', header: '' },
          { accessorKey: 'username', header: 'Username' },
          { id: 'role', header: 'Role' },
        ]"
      >
        <template #actions-cell="{ row }">
          <UButton
            size="xs"
            color="neutral"
            variant="ghost"
            icon="i-lucide-pencil"
            aria-label="Edit"
            title="Edit"
            @click="openEdit(row.original)"
          />
        </template>
        <template #role-cell="{ row }">
          {{ roleLabel(row.original.role) }}
          <span v-if="row.original.id === auth.user?.id" class="text-muted">(you)</span>
        </template>
      </UTable>
    </div>
  </div>

  <UModal
    :open="open"
    :title="editing ? 'Edit user' : 'New user'"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form id="user-form" class="space-y-3" @submit.prevent="save">
        <UFormField :ui="inlineField" label="Username" required>
          <UInput
            v-model="form.username"
            class="w-full"
            placeholder="username"
            :disabled="!!editing"
            required
          />
        </UFormField>
        <UFormField v-if="!editing" :ui="inlineField" label="Password" required>
          <UInput
            v-model="form.password"
            type="password"
            autocomplete="new-password"
            class="w-full"
            required
          />
        </UFormField>
        <UFormField
          :ui="inlineField"
          label="Role"
          :help="isSelf ? 'You cannot change your own role.' : ''"
        >
          <USelect v-model="form.role" :items="roles" class="w-full" :disabled="isSelf" />
        </UFormField>
      </form>
    </template>
    <template #footer>
      <div class="flex w-full gap-2">
        <UButton
          v-if="editing && !isSelf"
          color="error"
          variant="ghost"
          icon="i-lucide-trash"
          label="Delete"
          @click="remove"
        />
        <UButton
          v-if="editing && !isSelf"
          color="neutral"
          variant="ghost"
          icon="i-lucide-key-round"
          label="Reset password"
          @click="openPassword"
        />
        <UButton class="ms-auto" color="neutral" variant="ghost" @click="guard.close">
          Cancel
        </UButton>
        <UButton type="submit" form="user-form" :loading="saving">Save</UButton>
      </div>
    </template>
  </UModal>

  <UModal
    :open="pwOpen"
    :title="`Reset password for ${editing?.username}`"
    description="Their sessions are logged out."
    :ui="wideModal"
    :dismissible="false"
    @update:open="pwGuard.onUpdateOpen"
  >
    <template #body>
      <form id="password-form" class="space-y-3" @submit.prevent="savePassword">
        <UFormField :ui="inlineField" label="New password" help="At least 10 characters." required>
          <UInput
            v-model="pw.next"
            type="password"
            autocomplete="new-password"
            class="w-full"
            required
          />
        </UFormField>
        <UFormField
          :ui="inlineField"
          label="Repeat password"
          :error="pwMismatch ? 'The passwords do not match' : false"
          required
        >
          <UInput
            v-model="pw.repeat"
            type="password"
            autocomplete="new-password"
            class="w-full"
            required
          />
        </UFormField>
      </form>
    </template>
    <template #footer>
      <div class="flex w-full gap-2">
        <UButton class="ms-auto" color="neutral" variant="ghost" @click="pwGuard.close">
          Cancel
        </UButton>
        <UButton
          type="submit"
          form="password-form"
          :loading="pwSaving"
          :disabled="!pw.next || pw.next !== pw.repeat"
        >
          Set password
        </UButton>
      </div>
    </template>
  </UModal>
</template>
