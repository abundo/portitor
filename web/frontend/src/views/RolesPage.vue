<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import SearchInput from '@/components/SearchInput.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useConfirm } from '@/composables/useConfirm'
import { useFormGuard } from '@/composables/useFormGuard'
import { inlineField, wideModal } from '@/utils/form'
import { useSearch } from '@/utils/search'
import { useInstanceStore } from '@/stores/instances'

const toast = useToast()
const { confirmDelete } = useConfirm()
const instanceStore = useInstanceStore()
const roles = ref([])
const users = ref([])
const levels = [
  { label: 'Admin', value: 'admin' },
  { label: 'Viewer', value: 'viewer' },
]
const levelLabel = (level) => levels.find((l) => l.value === level)?.label ?? level
const userName = (id) => users.value.find((u) => u.id === id)?.username ?? `#${id}`
const instancesText = (r) => r.instance_ids.map((id) => instanceStore.nameOf(id)).join(', ')
const memberText = (r) =>
  r.members.map((m) => `${userName(m.user_id)} (${levelLabel(m.level)})`).join(', ')

async function load() {
  ;[roles.value, users.value] = await Promise.all([api.roles(), api.users()])
}
onMounted(load)
const { search, filtered: shownRoles } = useSearch(
  roles,
  (r) =>
    `${r.name} ${r.description} ${r.instance_id ? 'instance' : ''} ${instancesText(r)} ${memberText(r)}`,
)

// The dialog adds a role or edits one. An instance's role keeps its name
// and is deleted with the instance.
const open = ref(false)
const saving = ref(false)
const editing = ref(null)
const form = reactive({ name: '', description: '', instance_ids: [], members: [] })
const guard = useFormGuard(form, open)
const isInstanceRole = computed(() => !!editing.value?.instance_id)

// The users not yet in the form, for the "Add member" picker.
const addUserId = ref(null)
const freeUsers = computed(() =>
  users.value
    .filter((u) => !form.members.some((m) => m.user_id === u.id))
    .map((u) => ({ label: u.username, value: u.id })),
)

function openCreate() {
  editing.value = null
  Object.assign(form, { name: '', description: '', instance_ids: [], members: [] })
  addUserId.value = null
  open.value = true
}

function openEdit(r) {
  editing.value = r
  Object.assign(form, {
    name: r.name,
    description: r.description,
    instance_ids: [...r.instance_ids],
    members: r.members.map((m) => ({ user_id: m.user_id, level: m.level })),
  })
  addUserId.value = null
  open.value = true
}

function addMember() {
  if (addUserId.value == null) return
  form.members.push({ user_id: addUserId.value, level: 'viewer' })
  addUserId.value = null
}

async function save() {
  saving.value = true
  try {
    if (editing.value) await api.updateRole(editing.value.id, form)
    else await api.createRole(form)
    open.value = false
    await load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}

async function remove() {
  if (!(await confirmDelete(`role ${editing.value.name}`))) return
  try {
    await api.deleteRole(editing.value.id)
    open.value = false
    await load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <div class="card">
    <div class="mb-3 flex items-center justify-between gap-3">
      <div>
        <div class="text-lg font-semibold">Roles</div>
        <div class="text-sm text-muted">
          A role grants its members instances, each member as an admin (changes and deploys them) or
          a viewer. Each instance has a role of its own, added, renamed and removed with the
          instance. A user with the global role None sees only what their roles grant.
        </div>
      </div>
      <UButton icon="i-lucide-plus" label="Add" @click="openCreate" />
    </div>
    <div class="mb-2">
      <SearchInput v-model="search" />
    </div>
    <UTable
      :data="shownRoles"
      :columns="[
        { id: 'actions', header: '' },
        { accessorKey: 'name', header: 'Name' },
        { accessorKey: 'description', header: 'Description' },
        { id: 'instances', header: 'Instances' },
        { id: 'members', header: 'Members' },
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
      <template #name-cell="{ row }">
        <span class="font-medium">{{ row.original.name }}</span>
        <UBadge
          v-if="row.original.instance_id"
          class="ms-2"
          size="sm"
          color="neutral"
          variant="subtle"
          label="instance"
        />
      </template>
      <template #instances-cell="{ row }">
        <span v-if="row.original.instance_ids.length">{{ instancesText(row.original) }}</span>
        <span v-else class="text-muted">none</span>
      </template>
      <template #members-cell="{ row }">
        <span v-if="row.original.members.length">{{ memberText(row.original) }}</span>
        <span v-else class="text-muted">none</span>
      </template>
      <template #empty>
        <div class="py-6 text-center text-muted">No role matches.</div>
      </template>
    </UTable>
  </div>

  <UModal
    :open="open"
    :title="editing ? 'Edit role' : 'New role'"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form id="role-form" class="space-y-3" @submit.prevent="save">
        <UFormField
          :ui="inlineField"
          label="Name"
          :help="isInstanceRole ? 'Follows the instance\'s name.' : ''"
          required
        >
          <UInput v-model="form.name" class="w-full" :disabled="isInstanceRole" required />
        </UFormField>
        <UFormField :ui="inlineField" label="Description">
          <UInput v-model="form.description" class="w-full" />
        </UFormField>
        <UFormField
          :ui="inlineField"
          label="Instances"
          :help="
            isInstanceRole
              ? 'An instance\'s role grants just that instance.'
              : 'Members get their level on each of these instances.'
          "
        >
          <USelectMenu
            v-model="form.instance_ids"
            :items="instanceStore.list.map((i) => ({ label: i.name, value: i.id }))"
            value-key="value"
            multiple
            class="w-full"
            placeholder="No instances"
            :disabled="isInstanceRole"
          />
        </UFormField>
        <UFormField :ui="inlineField" label="Members">
          <div class="space-y-2">
            <div v-for="(m, i) in form.members" :key="m.user_id" class="flex items-center gap-2">
              <span class="min-w-0 flex-1 truncate">{{ userName(m.user_id) }}</span>
              <USelect v-model="m.level" :items="levels" class="w-32" />
              <UButton
                color="neutral"
                variant="ghost"
                icon="i-lucide-x"
                aria-label="Remove member"
                title="Remove member"
                @click="form.members.splice(i, 1)"
              />
            </div>
            <div v-if="freeUsers.length" class="flex items-center gap-2">
              <USelect
                v-model="addUserId"
                :items="freeUsers"
                placeholder="Add a user…"
                class="flex-1"
              />
              <UButton
                color="neutral"
                variant="outline"
                icon="i-lucide-user-plus"
                label="Add"
                :disabled="addUserId == null"
                @click="addMember"
              />
            </div>
          </div>
        </UFormField>
      </form>
    </template>
    <template #footer>
      <div class="flex w-full gap-2">
        <UButton
          v-if="editing && !isInstanceRole"
          color="error"
          variant="ghost"
          icon="i-lucide-trash"
          label="Delete"
          @click="remove"
        />
        <UButton class="ms-auto" color="neutral" variant="ghost" @click="guard.close">
          Cancel
        </UButton>
        <UButton type="submit" form="role-form" :loading="saving">Save</UButton>
      </div>
    </template>
  </UModal>
</template>
