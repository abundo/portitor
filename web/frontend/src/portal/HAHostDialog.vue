<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// HAHostDialog: adds a host (primary or secondary) to an HA firewall over
// SSH, its host key confirmed first. When the other host is there and the
// two are not a pair yet, the portal pairs them, which needs the login to
// the other host too (its address and host key are the portal's). Nothing
// is copied by hand, and the credentials are not kept.
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { useFormGuard } from '@/composables/useFormGuard'
import { wideModal } from '@/utils/form'
import SshFields from './SshFields.vue'
import { portal } from './api'

const open = defineModel('open', { type: Boolean, default: false })
const props = defineProps({
  // firewall: the HA firewall's status (GET firewalls).
  firewall: { type: Object, required: true },
  role: { type: String, required: true },
})
const emit = defineEmits(['saved'])
const toast = useToast()

const blank = () => ({ host: '', port: 22, user: 'portitor', password: '', private_key: '' })
const ssh = reactive(blank())
const other = reactive(blank())
const hostKey = ref('')
const busy = ref(false)
const otherRole = computed(() => (props.role === 'primary' ? 'secondary' : 'primary'))
const otherHost = computed(() => props.firewall.hosts?.find((h) => h.role === otherRole.value))
// needOther: pairing must run, so the other host's login is asked for.
const needOther = ref(false)
const guard = useFormGuard(ssh, open)

watch(open, (o) => {
  if (!o) return
  Object.assign(ssh, blank())
  Object.assign(other, blank())
  hostKey.value = ''
  // Asked for when the server answers that the hosts must be paired (409).
  needOther.value = false
})

async function add() {
  busy.value = true
  try {
    const req = {
      ssh: { ...ssh, port: ssh.port || 22, host: ssh.host.trim(), host_key: hostKey.value },
    }
    if (needOther.value) req.other = { ...other, port: other.port || 22 }
    const res = await portal.addHAHost(props.firewall.name, props.role, req)
    if (res.confirm) {
      hostKey.value = res.host_key
      return
    }
    open.value = false
    emit('saved')
    if (res.paired)
      toast.add({ title: `${props.firewall.name}: the hosts are paired`, color: 'success' })
    else if (res.connected)
      toast.add({ title: `${props.firewall.name}: the hosts are a pair already`, color: 'info' })
    if (res.warning) toast.add({ title: 'Added, but', description: res.warning, color: 'warning' })
  } catch (e) {
    if (e.status === 409 && otherHost.value) {
      // Not an error: the second step, with the other host's login.
      needOther.value = true
      return
    }
    toast.add({ title: 'Host not added', description: e.message, color: 'error' })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <UModal
    :open="open"
    :title="`${firewall.name}: add the ${role}`"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form id="ha-host-form" class="space-y-3" @submit.prevent="add">
        <p class="text-sm text-muted">
          <template v-if="role === 'secondary'">
            The host installed from the ISO with role secondary, at its management address.
          </template>
          <template v-else>The host installed as the pair's primary.</template>
          Portitor logs in over SSH to read its portitor-config's address and certificate. The
          credentials are not kept.
        </p>
        <SshFields v-model="ssh" :host-key="hostKey" :what="`The ${role}`" />
        <template v-if="needOther">
          <div class="pt-2 text-sm font-semibold">The {{ otherRole }} ({{ otherHost?.url }})</div>
          <p class="text-sm text-muted">
            The two hosts are not a pair yet: Portitor logs in to the {{ otherRole }} too, hands the
            secondary's details from one to the other and commits the pair. Its host key was
            confirmed when it was added.
          </p>
          <SshFields v-model="other" :host="false" />
        </template>
      </form>
    </template>
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton color="neutral" variant="ghost" @click="guard.close">Cancel</UButton>
        <UButton type="submit" form="ha-host-form" :loading="busy">
          {{ hostKey ? 'Trust this host key and add' : needOther ? 'Add and pair' : 'Add' }}
        </UButton>
      </div>
    </template>
  </UModal>
</template>
