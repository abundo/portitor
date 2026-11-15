<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// FirewallDialog: a firewall of the portal. New: the portal logs in over SSH
// once (portitor-config portal-info) for its portitor-config's address and
// certificate fingerprint, the host key confirmed first; or they are entered
// by hand. Edit: its description, address and fingerprint, and Delete.
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { useFormGuard } from '@/composables/useFormGuard'
import { useConfirm } from '@/composables/useConfirm'
import { inlineField, wideModal } from '@/utils/form'
import SshFields from './SshFields.vue'
import { portal } from './api'

const open = defineModel('open', { type: Boolean, default: false })
// row: the firewall being edited; null for a new one.
const props = defineProps({ row: { type: Object, default: null } })
const emit = defineEmits(['saved'])
const toast = useToast()
const { confirmDelete } = useConfirm()

const ssh = reactive({ host: '', port: 22, user: 'root', password: '', private_key: '' })
const form = reactive({ name: '', description: '', url: '', fingerprint: '', ssh_host_key: '' })
const hostKey = ref('')
const found = ref(false)
const busy = ref(false)
const isNew = computed(() => !props.row)
const guard = useFormGuard(form, open)

watch(open, (o) => {
  if (!o) return
  Object.assign(ssh, { host: '', port: 22, user: 'root', password: '', private_key: '' })
  hostKey.value = ''
  const r = props.row
  Object.assign(form, {
    name: r?.name ?? '',
    description: r?.description ?? '',
    url: r?.url ?? '',
    fingerprint: r?.fingerprint ?? '',
    ssh_host_key: '',
  })
  found.value = !!r
})

async function connect() {
  busy.value = true
  try {
    const res = await portal.probe({
      ...ssh,
      port: ssh.port || 22,
      host: ssh.host.trim(),
      host_key: hostKey.value,
    })
    if (res.confirm) {
      hostKey.value = res.host_key
      return
    }
    form.url = res.url
    form.fingerprint = res.info?.fingerprint ?? ''
    form.ssh_host_key = hostKey.value
    if (!form.name) form.name = ssh.host.trim().split('.')[0]
    found.value = true
  } catch (e) {
    toast.add({ title: 'Could not read the firewall', description: e.message, color: 'error' })
  } finally {
    busy.value = false
  }
}

async function save() {
  busy.value = true
  try {
    const f = {
      ...form,
      name: form.name.trim(),
      description: form.description.trim(),
      url: form.url.trim(),
    }
    if (isNew.value) await portal.addFirewall(f)
    else await portal.putFirewall({ ...f, ssh_host_key: props.row.ssh_host_key })
    open.value = false
    emit('saved', f.name)
  } catch (e) {
    toast.add({ title: 'Not saved', description: e.message, color: 'error' })
  } finally {
    busy.value = false
  }
}

async function remove() {
  if (
    !(await confirmDelete(
      `firewall ${props.row.name}`,
      'The portal stops serving it; the firewall is not changed.',
    ))
  )
    return
  try {
    await portal.deleteFirewall(props.row.name)
    open.value = false
    emit('saved')
  } catch (e) {
    toast.add({ title: 'Not deleted', description: e.message, color: 'error' })
  }
}
</script>

<template>
  <UModal
    :open="open"
    :title="isNew ? 'Add firewall' : `Firewall ${row.name}`"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form id="firewall-form" class="space-y-3" @submit.prevent="found ? save() : connect()">
        <template v-if="!found">
          <p class="text-sm text-muted">
            Portitor logs in to the firewall over SSH once to read its portitor-config's address and
            certificate fingerprint. The credentials are not kept.
          </p>
          <SshFields v-model="ssh" :host-key="hostKey" what="The firewall" />
        </template>
        <template v-else>
          <UFormField :ui="inlineField" label="Name" required help="Its tab and path: /fw/<name>/.">
            <UInput v-model="form.name" class="w-full" :disabled="!isNew" autocomplete="off" />
          </UFormField>
          <UFormField :ui="inlineField" label="Description">
            <UInput v-model="form.description" class="w-full" autocomplete="off" />
          </UFormField>
          <UFormField :ui="inlineField" label="portitor-config URL" required>
            <UInput v-model="form.url" class="w-full" placeholder="https://192.0.2.1:8444" />
          </UFormField>
          <UFormField
            :ui="inlineField"
            label="Certificate fingerprint"
            help="SHA-256 of its tls_cert."
          >
            <UInput v-model="form.fingerprint" class="w-full font-mono" />
          </UFormField>
        </template>
      </form>
    </template>
    <template #footer>
      <div class="flex w-full items-center gap-2">
        <UButton
          v-if="!isNew"
          color="error"
          variant="outline"
          icon="i-lucide-trash-2"
          @click="remove"
        >
          Delete
        </UButton>
        <UButton v-if="isNew && !found" color="neutral" variant="ghost" @click="found = true">
          Enter by hand
        </UButton>
        <div class="ml-auto flex gap-2">
          <UButton color="neutral" variant="ghost" @click="guard.close">Cancel</UButton>
          <UButton type="submit" form="firewall-form" :loading="busy">
            {{ found ? 'Save' : hostKey ? 'Trust this host key and connect' : 'Connect' }}
          </UButton>
        </div>
      </div>
    </template>
  </UModal>
</template>
