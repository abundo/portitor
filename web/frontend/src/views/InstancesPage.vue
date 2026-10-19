<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import { instances } from '@/api'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useConfirm } from '@/composables/useConfirm'
import { useInstanceStore } from '@/stores/instances'

const store = useInstanceStore()
const toast = useToast()
const { ask } = useConfirm()

// A virtual firewall a manager pushed is read-only here; break-glass lets
// it be edited, and the manager sees that it changed here.
async function breakGlass(form) {
  if (
    !(await ask({
      title: 'Break glass',
      message: `Edit ${form.name} here, though ${form.managed_by} manages it?`,
      detail: `${form.managed_by} then sees it changed here, and takes this version or overwrites it.`,
    }))
  )
    return
  try {
    await api.breakGlass(form.id)
    form.diverged = true
    toast.add({ title: `${form.name} can be edited here`, color: 'warning' })
    store.load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'firewall_id', label: 'Firewall', format: (r) => store.firewallName(r.firewall_id) },
  { key: 'description', label: 'Description' },
  {
    key: 'managed_by',
    label: 'Managed by',
    format: (r) =>
      r.managed_by ? (r.diverged ? `${r.managed_by} (changed here)` : r.managed_by) : '',
  },
]

const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'guest',
    hint: 'Lowercase letters and digits, max 12. Runs in network namespace fw-<name>.',
  },
  {
    key: 'firewall_id',
    label: 'Firewall',
    type: 'select',
    items: () => store.firewallItems,
    show: () => store.firewalls.length > 1,
    hint: 'The host it runs on. One with links stays on its firewall.',
  },
  { key: 'description', label: 'Description' },
  { key: 'managed_by', label: 'Managed by', type: 'custom', show: (f) => !!f.managed_by },
]
</script>

<template>
  <CrudPage
    title="Virtual firewalls"
    description="Virtual routers, each in its own network namespace, with its own interfaces, routing table, firewall, DNS and DHCP server. Each firewall's host is its default virtual firewall and is not listed. Connect virtual firewalls with links."
    :api="instances"
    shared
    :columns="columns"
    :fields="fields"
    :row-filter="(i) => !i.is_default"
    new-label="New virtual firewall"
    @changed="store.load()"
  >
    <template #field-managed_by="{ form }">
      <div class="flex items-center gap-2">
        <span>{{ form.managed_by }}</span>
        <UBadge v-if="form.diverged" color="warning" variant="subtle" label="changed here" />
        <UButton
          v-else
          size="xs"
          variant="outline"
          color="warning"
          label="Break glass"
          @click="breakGlass(form)"
        />
      </div>
    </template>
  </CrudPage>
</template>
