<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// HADialog: an HA firewall, a pair served as one firewall from whichever of
// its hosts is primary now. Its name, description and whether the portal is
// to be the pair's witness; edited, its two hosts as they answer, each added
// (HAHostDialog) or removed, and Delete. Adding the second host pairs them.
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { confirmDiscard, useFormGuard } from '@/composables/useFormGuard'
import { useConfirm } from '@/composables/useConfirm'
import { inlineField, wideModal } from '@/utils/form'
import HAHostDialog from './HAHostDialog.vue'
import { portal } from './api'

const open = defineModel('open', { type: Boolean, default: false })
// row: the HA firewall's status (GET firewalls); null for a new one.
const props = defineProps({ row: { type: Object, default: null } })
const emit = defineEmits(['saved', 'created'])
const toast = useToast()
const { confirmDelete, ask } = useConfirm()

const form = reactive({ name: '', description: '', witness: true })
const busy = ref(false)
const isNew = computed(() => !props.row)
const guard = useFormGuard(form, open)
const hostOpen = ref(false)
const hostRole = ref('primary')

watch(open, (o) => {
  if (!o) return
  Object.assign(form, {
    name: props.row?.name ?? '',
    description: props.row?.description ?? '',
    witness: props.row ? !!props.row.witness : true,
  })
})

const roles = ['primary', 'secondary']
const hostOf = (role) => props.row?.hosts?.find((h) => h.role === role)

function stateOf(h) {
  if (h.error) return { color: 'error', label: h.error }
  if (!h.known) return { color: 'neutral', label: 'role unknown' }
  if (h.replica) return { color: 'neutral', label: 'replica' }
  return { color: 'success', label: 'primary now' }
}

async function save() {
  busy.value = true
  try {
    const ha = { ...form, name: form.name.trim(), description: form.description.trim() }
    if (isNew.value) await portal.addHA(ha)
    else await portal.putHA(ha)
    const created = isNew.value
    open.value = false
    // A new one opens again at once, edited, for its hosts.
    emit(created ? 'created' : 'saved', ha.name)
  } catch (e) {
    toast.add({ title: 'Not saved', description: e.message, color: 'error' })
  } finally {
    busy.value = false
  }
}

function addHost(role) {
  hostRole.value = role
  hostOpen.value = true
}

async function openHost(h) {
  if (await confirmDiscard()) window.location.assign(h.path)
}

async function removeHost(role) {
  const ok = await ask({
    title: 'Remove host',
    message: `Remove the ${role} host from ${props.row.name}?`,
    detail: 'portitor-manager forgets it; the cluster is not changed.',
  })
  if (!ok) return
  try {
    await portal.removeHAHost(props.row.name, role)
    emit('saved')
  } catch (e) {
    toast.add({ title: 'Not removed', description: e.message, color: 'error' })
  }
}

async function remove() {
  if (
    !(await confirmDelete(
      `Firewall cluster ${props.row.name}`,
      'portitor-manager stops serving it; the cluster is not changed. If portitor-manager is its witness, the witness string stays under Cluster witness.',
    ))
  )
    return
  try {
    await portal.deleteHA(props.row.name)
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
    :title="isNew ? 'Add firewall cluster' : `Firewall cluster ${row.name}`"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form id="ha-form" class="space-y-3" @submit.prevent="save">
        <p v-if="isNew" class="text-sm text-muted">
          A firewall cluster as one firewall: served from whichever firewall is primary now. Add its
          primary and its secondary next (install the secondary from the ISO, role secondary); once
          both are here portitor-manager sets up the cluster over SSH, unless they are a cluster
          already.
        </p>
        <UFormField :ui="inlineField" label="Name" required help="Its path: /fw/<name>/.">
          <UInput v-model="form.name" class="w-full" :disabled="!isNew" autocomplete="off" />
        </UFormField>
        <UFormField :ui="inlineField" label="Description">
          <UInput v-model="form.description" class="w-full" autocomplete="off" />
        </UFormField>
        <UFormField
          :ui="inlineField"
          label="Witness"
          help="When it sets up the cluster, portitor-manager becomes its witness. It must reach both firewalls' management addresses."
        >
          <USwitch v-model="form.witness" />
        </UFormField>
        <template v-if="!isNew">
          <div class="pt-2 text-sm font-semibold">Hosts</div>
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-muted">
                <th class="py-1 pr-2 font-medium">Installed as</th>
                <th class="py-1 pr-2 font-medium">portitor-config</th>
                <th class="py-1 pr-2 font-medium">Now</th>
                <th class="py-1" />
              </tr>
            </thead>
            <tbody>
              <tr v-for="role in roles" :key="role" class="border-t border-default">
                <td class="py-1 pr-2 capitalize">{{ role }}</td>
                <template v-if="hostOf(role)">
                  <td class="py-1 pr-2 font-mono text-xs">{{ hostOf(role).url }}</td>
                  <td class="py-1 pr-2">
                    <UBadge variant="subtle" v-bind="stateOf(hostOf(role))" />
                  </td>
                  <td class="py-1 text-right whitespace-nowrap">
                    <UButton
                      size="xs"
                      color="neutral"
                      variant="ghost"
                      icon="i-lucide-external-link"
                      :disabled="!!hostOf(role).error"
                      title="Open this firewall's GUI alone (its own login)"
                      @click="openHost(hostOf(role))"
                    >
                      Open
                    </UButton>
                    <UButton
                      size="xs"
                      color="neutral"
                      variant="ghost"
                      icon="i-lucide-x"
                      @click="removeHost(role)"
                    >
                      Remove
                    </UButton>
                  </td>
                </template>
                <template v-else>
                  <td class="py-1 pr-2 text-muted" colspan="2">not added</td>
                  <td class="py-1 text-right">
                    <UButton size="xs" icon="i-lucide-plus" @click="addHost(role)">Add</UButton>
                  </td>
                </template>
              </tr>
            </tbody>
          </table>
          <UAlert
            v-if="row.hosts?.length === 2"
            :color="row.connected ? 'success' : 'warning'"
            variant="subtle"
            :title="row.connected ? 'The hosts are a pair.' : 'The hosts are not a pair (yet).'"
            :description="
              row.connected
                ? undefined
                : 'Remove one of them and add it again: portitor-manager sets up the cluster when the second is added.'
            "
          />
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
        <div class="ml-auto flex gap-2">
          <UButton color="neutral" variant="ghost" @click="guard.close">Cancel</UButton>
          <UButton type="submit" form="ha-form" :loading="busy">Save</UButton>
        </div>
      </div>
    </template>
  </UModal>
  <HAHostDialog
    v-if="row"
    v-model:open="hostOpen"
    :firewall="row"
    :role="hostRole"
    @saved="emit('saved')"
  />
</template>
