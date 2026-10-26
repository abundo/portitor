<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- A role's form on the Directory page: a new role (role null) or an
     existing one. An instance's role keeps its name and is deleted with the
     instance. saved gives the saved role, deleted tells it is gone. -->
<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import FormHeader from '@/components/FormHeader.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useConfirm } from '@/composables/useConfirm'
import { usePageForm } from '@/composables/useFormGuard'
import { inlineField } from '@/utils/form'
import { useInstanceStore } from '@/stores/instances'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  role: { type: Object, default: null },
  users: { type: Array, default: () => [] },
})
const emit = defineEmits(['saved', 'deleted'])
const toast = useToast()
const { confirmDelete } = useConfirm()
const instanceStore = useInstanceStore()
const auth = useAuthStore()
const levels = [
  { label: 'Admin', value: 'admin' },
  { label: 'Viewer', value: 'viewer' },
]
const userName = (id) => props.users.find((u) => u.id === id)?.username ?? `#${id}`

const form = reactive({ name: '', description: '', instance_ids: [], members: [] })
const guard = usePageForm(form)
const saving = ref(false)
const editing = computed(() => props.role)
const isInstanceRole = computed(() => !!editing.value?.instance_id)

onMounted(() => {
  const r = props.role
  Object.assign(form, {
    name: r?.name ?? '',
    description: r?.description ?? '',
    instance_ids: [...(r?.instance_ids ?? [])],
    members: (r?.members ?? []).map((m) => ({ user_id: m.user_id, level: m.level })),
  })
  guard.mark()
})

// The users not yet in the form, for the "Add member" picker.
const addUserId = ref(null)
const freeUsers = computed(() =>
  props.users
    .filter((u) => !form.members.some((m) => m.user_id === u.id))
    .map((u) => ({ label: u.username, value: u.id })),
)
function addMember() {
  if (addUserId.value == null) return
  form.members.push({ user_id: addUserId.value, level: 'viewer' })
  addUserId.value = null
}

async function save() {
  saving.value = true
  try {
    const saved = editing.value
      ? await api.updateRole(editing.value.id, form)
      : await api.createRole(form)
    toast.add({ title: `Role ${saved?.name ?? form.name} saved`, color: 'success' })
    guard.mark()
    emit('saved', saved)
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
    guard.mark()
    emit('deleted')
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <form class="card" @submit.prevent="save">
    <FormHeader :title="editing ? `Role ${editing.name}` : 'New role'">
      <UButton
        v-if="editing && !isInstanceRole"
        color="error"
        variant="ghost"
        icon="i-lucide-trash"
        label="Delete"
        @click="remove"
      />
      <UButton type="submit" :loading="saving" :disabled="!guard.dirty()">Save</UButton>
    </FormHeader>
    <p class="mb-3 text-sm text-muted">
      A role grants its members instances, each member as an admin (changes and deploys them) or a
      viewer. Each virtual firewall but the host has a role of its own, added, renamed and removed
      with the virtual firewall. A user with the global role None sees only what their roles grant.
    </p>
    <div class="space-y-3">
      <UFormField
        :ui="inlineField"
        label="Name"
        :help="isInstanceRole ? 'Follows the virtual firewall\'s name.' : ''"
        required
      >
        <UInput v-model="form.name" class="w-full" :disabled="isInstanceRole" required />
      </UFormField>
      <UFormField :ui="inlineField" label="Description">
        <UInput v-model="form.description" class="w-full" />
      </UFormField>
      <UFormField
        v-if="auth.user?.virtual_firewalls"
        :ui="inlineField"
        label="Virtual firewalls"
        :help="
          isInstanceRole
            ? 'A virtual firewall\'s role grants just that virtual firewall.'
            : 'Members get their level on each of these virtual firewalls.'
        "
      >
        <USelectMenu
          v-model="form.instance_ids"
          :items="instanceStore.list.map((i) => ({ label: i.name, value: i.id }))"
          value-key="value"
          multiple
          class="w-full"
          placeholder="No virtual firewalls"
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
    </div>
  </form>
</template>
