<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- A user's form on the Directory page: a new user (user null) or an
     existing one. saved gives the saved user, deleted tells it is gone. -->
<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import FormHeader from '@/components/FormHeader.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useConfirm } from '@/composables/useConfirm'
import { usePageForm } from '@/composables/useFormGuard'
import { inlineField } from '@/utils/form'

const props = defineProps({ user: { type: Object, default: null } })
const emit = defineEmits(['saved', 'deleted'])
const toast = useToast()
const auth = useAuthStore()
const { ask, confirmDelete } = useConfirm()
const roles = [
  { label: 'Admin', value: 'admin', description: 'Changes and deploys everything' },
  { label: 'Viewer', value: 'viewer', description: 'Reads the configuration and status' },
  { label: 'None', value: 'none', description: 'Only the virtual firewalls their roles grant' },
]

const form = reactive({
  username: '',
  password: '',
  repeat: '',
  role: 'viewer',
  totp_required: false,
})
const guard = usePageForm(form)
const saving = ref(false)
const editing = computed(() => props.user)
const isSelf = computed(() => editing.value?.id === auth.user?.id)
const mismatch = computed(() => form.repeat !== '' && form.password !== form.repeat)
// A new user needs a password; an existing one (not you: Change password)
// gets one only when it is typed.
const passwordShown = computed(() => !editing.value || !isSelf.value)

// A new user starts "Require two-factor login" from the default under
// Settings.
onMounted(async () => {
  const u = props.user
  let totp = !!u?.totp_required
  if (!u)
    try {
      totp = !!(await api.settings()).totp_default
    } catch (err) {
      toast.add({ title: errMsg(err), color: 'error' })
    }
  Object.assign(form, {
    username: u?.username ?? '',
    password: '',
    repeat: '',
    role: u?.role ?? 'viewer',
    totp_required: totp,
  })
  guard.mark()
})

async function save() {
  if (form.password !== form.repeat) {
    toast.add({ title: 'The passwords do not match', color: 'error' })
    return
  }
  saving.value = true
  try {
    let saved = editing.value
    if (!saved) {
      saved = await api.createUser(form.username, form.password, form.role, form.totp_required)
      toast.add({ title: `User ${saved.username} added`, color: 'success' })
    } else {
      if (form.role !== saved.role || form.totp_required !== !!saved.totp_required)
        saved = await api.updateUser(saved.id, {
          role: form.role,
          totp_required: form.totp_required,
        })
      if (form.password) await api.setUserPassword(saved.id, form.password)
      toast.add({
        title: form.password
          ? `User ${saved.username} saved; their sessions are logged out`
          : `User ${saved.username} saved`,
        color: 'success',
      })
    }
    form.password = form.repeat = ''
    guard.mark()
    emit('saved', saved)
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}

async function resetTotp() {
  const u = editing.value
  const ok = await ask({
    title: 'Reset two-factor login',
    message: u.totp_required
      ? `Turn off two-factor login for ${u.username}? It is required of them, so they must set it up again at their next login.`
      : `Turn off two-factor login for ${u.username}? They log in with their password alone and can set it up again.`,
  })
  if (!ok) return
  try {
    await api.resetUserTotp(u.id)
    toast.add({ title: `Two-factor login of ${u.username} is off`, color: 'success' })
    emit('saved', { ...u, totp_enabled: false })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

async function remove() {
  if (!(await confirmDelete(`user ${editing.value.username}`))) return
  try {
    await api.deleteUser(editing.value.id)
    guard.mark()
    emit('deleted')
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <form class="card" @submit.prevent="save">
    <FormHeader :title="editing ? `User ${editing.username}` : 'New user'">
      <UButton
        v-if="editing && !isSelf && editing.totp_enabled"
        color="neutral"
        variant="outline"
        icon="i-lucide-shield-off"
        label="Reset 2FA"
        @click="resetTotp"
      />
      <UButton
        v-if="editing && !isSelf"
        color="error"
        variant="ghost"
        icon="i-lucide-trash"
        label="Delete"
        @click="remove"
      />
      <UButton type="submit" :loading="saving" :disabled="!guard.dirty() || mismatch">
        Save
      </UButton>
    </FormHeader>
    <div class="space-y-3">
      <UFormField :ui="inlineField" label="Username" required>
        <UInput
          v-model="form.username"
          class="w-full"
          placeholder="username"
          :disabled="!!editing"
          required
        />
      </UFormField>
      <UFormField v-if="editing" :ui="inlineField" label="From">
        <span v-if="editing.ldap_server">
          The directory server {{ editing.ldap_server }}, at their first login: their password is
          checked there, and the roles its groups map to follow their groups.
        </span>
        <span v-else>Local</span>
      </UFormField>
      <UFormField v-if="editing" :ui="inlineField" label="Two-factor login">
        <span v-if="editing.totp_enabled">On</span>
        <span v-else-if="editing.totp_required">Required, not set up</span>
        <span v-else class="text-muted">Off</span>
      </UFormField>
      <UFormField
        v-if="passwordShown"
        :ui="inlineField"
        :label="!editing ? 'Password' : editing.ldap_server ? 'Local password' : 'New password'"
        :help="
          editing
            ? 'Empty: unchanged. Setting it logs out their sessions.'
            : 'At least 10 characters.'
        "
        :required="!editing"
      >
        <UInput
          v-model="form.password"
          type="password"
          autocomplete="new-password"
          class="w-full"
          :required="!editing"
        />
      </UFormField>
      <UFormField
        v-if="passwordShown && (form.password || !editing)"
        :ui="inlineField"
        label="Repeat password"
        :error="mismatch ? 'The passwords do not match' : false"
        required
      >
        <UInput
          v-model="form.repeat"
          type="password"
          autocomplete="new-password"
          class="w-full"
          required
        />
      </UFormField>
      <UFormField
        :ui="inlineField"
        label="Role"
        :help="
          isSelf ? 'You cannot change your own role; your password is under Change password.' : ''
        "
      >
        <USelect v-model="form.role" :items="roles" class="w-full" :disabled="isSelf" />
      </UFormField>
      <UFormField
        :ui="inlineField"
        label="Require two-factor login"
        help="The user must set up two-factor login (TOTP) before they can do anything else."
      >
        <USwitch v-model="form.totp_required" />
      </UFormField>
    </div>
  </form>
</template>
