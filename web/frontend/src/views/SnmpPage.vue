<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- SNMP (net-snmp's snmpd), read-only, for management platforms: the
     agent's settings, the interfaces it answers on and its SNMPv3 users. -->
<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import AddrInput from '@/components/AddrInput.vue'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { instances, interfaces, snmpUsers } from '@/api'
import { errMsg } from '@/api/http'
import { withLabel } from '@/composables/useInstanceRefs'
import { usePageForm } from '@/composables/useFormGuard'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { inlineField } from '@/utils/form'
import { useSearch } from '@/utils/search'

const toast = useToast()
const auth = useAuthStore()
const store = useInstanceStore()
const readOnly = computed(() => !auth.canEdit)

// The instance's snmp_* fields, and its interfaces' snmp_serve.
const form = reactive({
  snmp_enabled: false,
  snmp_location: '',
  snmp_contact: '',
  snmp_allow: [],
  new_snmp_community: '',
  clear_snmp_community: false,
  has_snmp_community: false,
  ifaces: [], // { id, name, label, description, snmp_serve }
})
const pageForm = usePageForm(form)
const saving = ref(false)
let loaded = [] // the interfaces as loaded, to save only what changed

async function load() {
  const id = store.currentId
  if (!id) return
  const [inst, ifs] = await Promise.all([instances.get(id), interfaces.list({ instance_id: id })])
  loaded = ifs
  Object.assign(form, {
    snmp_enabled: inst.snmp_enabled ?? false,
    snmp_location: inst.snmp_location ?? '',
    snmp_contact: inst.snmp_contact ?? '',
    snmp_allow: inst.snmp_allow ?? [],
    new_snmp_community: '',
    clear_snmp_community: false,
    has_snmp_community: !!inst.has_snmp_community,
    ifaces: ifs.map((i) => ({
      id: i.id,
      name: i.name,
      label: i.label,
      description: i.description,
      snmp_serve: i.snmp_serve ?? false,
    })),
  })
  pageForm.mark()
}
watch(() => store.currentId, load, { immediate: true })

const { search: ifaceSearch, filtered: shownIfaces } = useSearch(
  () => form.ifaces,
  (i) => `${withLabel(i.label, i.name)} ${i.description}`,
)

async function save() {
  saving.value = true
  try {
    const { ifaces, ...snmp } = form
    delete snmp.has_snmp_community
    await instances.update(store.currentId, snmp)
    for (const i of ifaces) {
      const o = loaded.find((x) => x.id === i.id)
      if (o && !!o.snmp_serve !== i.snmp_serve)
        await interfaces.update(i.id, { snmp_serve: i.snmp_serve })
    }
    toast.add({ title: 'SNMP saved; commit to apply it.', color: 'success' })
    await Promise.all([load(), store.load()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}

// ----- SNMPv3 users.
const authItems = [
  { label: 'SHA-256', value: 'SHA-256' },
  { label: 'SHA-512', value: 'SHA-512' },
  { label: 'SHA (SHA-1)', value: 'SHA' },
]
const privItems = [
  { label: 'AES (128)', value: 'AES' },
  { label: 'none (authentication only)', value: '' },
]
const userColumns = [
  { key: 'name', label: 'User', class: 'font-mono' },
  { key: 'enabled', label: 'Enabled' },
  { key: 'auth_protocol', label: 'Authentication' },
  { key: 'priv_protocol', label: 'Privacy', format: (u) => u.priv_protocol || 'none' },
  { key: 'description', label: 'Description' },
]
const userFields = [
  { key: 'name', label: 'User name', required: true, placeholder: 'monitor' },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
  { key: 'auth_protocol', label: 'Authentication', type: 'select', items: authItems },
  { key: 'auth_password', label: 'Authentication password', type: 'custom' },
  {
    key: 'priv_protocol',
    label: 'Privacy',
    type: 'select',
    items: privItems,
    hint: 'Encrypts the requests and answers (authPriv). None: authNoPriv.',
  },
  {
    key: 'priv_password',
    label: 'Privacy password',
    type: 'custom',
    show: (f) => !!f.priv_protocol,
  },
]
const userDefaults = {
  name: '',
  enabled: true,
  description: '',
  auth_protocol: 'SHA-256',
  priv_protocol: 'AES',
}
</script>

<template>
  <NeedInstance>
    <div class="space-y-4">
      <div class="card">
        <form @submit.prevent="save">
          <h2 class="border-b border-default pb-1 mb-2 text-xl font-semibold">SNMP</h2>
          <p class="mb-4 text-sm text-muted">
            An SNMP agent (net-snmp) lets management platforms monitor this virtual firewall:
            interfaces and their traffic, addresses and routes, system load, memory and disks. It is
            read-only. On a virtual firewall other than the default it sees that virtual firewall's
            own interfaces. Changes take effect when committed.
          </p>
          <fieldset :disabled="readOnly" class="space-y-3">
            <UFormField label="Enabled" :ui="inlineField">
              <USwitch v-model="form.snmp_enabled" />
            </UFormField>
            <UFormField label="Location" help="sysLocation." :ui="inlineField">
              <UInput v-model="form.snmp_location" class="w-full" placeholder="Server room 1" />
            </UFormField>
            <UFormField label="Contact" help="sysContact." :ui="inlineField">
              <UInput v-model="form.snmp_contact" class="w-full" placeholder="noc@example.com" />
            </UFormField>
            <UFormField
              label="SNMPv2c community"
              help="Read-only. Sent in clear text: prefer SNMPv3 users where the platform supports them. Empty: no SNMPv2c."
              :ui="inlineField"
            >
              <div class="flex w-full flex-wrap items-center gap-2">
                <UInput
                  v-model="form.new_snmp_community"
                  type="password"
                  autocomplete="new-password"
                  class="min-w-48 flex-1"
                  :disabled="form.clear_snmp_community"
                  :placeholder="form.has_snmp_community ? 'set; leave empty to keep it' : 'none'"
                />
                <USwitch
                  v-if="form.has_snmp_community"
                  v-model="form.clear_snmp_community"
                  label="Remove"
                />
              </div>
            </UFormField>
          </fieldset>

          <h2 class="border-b border-default pb-1 mt-8 mb-2 text-xl font-semibold">
            Answering requests
          </h2>
          <p class="mb-4 text-sm text-muted">
            The firewall answers SNMP requests (UDP port 161) on the interfaces turned on here, and
            of those only from the allowed clients.
          </p>
          <!-- Outside the form's fieldset, so a viewer can search too. -->
          <div class="mb-2">
            <SearchInput v-model="ifaceSearch" />
          </div>
          <fieldset :disabled="readOnly" class="min-w-0 overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-default text-left text-xs text-muted">
                  <th class="py-1 pr-4 font-medium">Interface</th>
                  <th class="pr-4 font-medium">Description</th>
                  <th class="pr-4 font-medium">Answer SNMP</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="i in shownIfaces"
                  :key="i.id"
                  class="border-b border-default last:border-0"
                >
                  <td class="py-1 pr-4 font-mono">{{ withLabel(i.label, i.name) }}</td>
                  <td class="py-1 pr-4">{{ i.description }}</td>
                  <td class="py-1 pr-4">
                    <USwitch v-model="i.snmp_serve" :aria-label="`Answer SNMP on ${i.name}`" />
                  </td>
                </tr>
                <tr v-if="!shownIfaces.length">
                  <td colspan="3" class="py-2 text-muted">
                    {{
                      form.ifaces.length
                        ? 'No interface matches.'
                        : 'This virtual firewall has no interfaces.'
                    }}
                  </td>
                </tr>
              </tbody>
            </table>
          </fieldset>
          <fieldset :disabled="readOnly" class="mt-3 space-y-3">
            <UFormField
              label="Allowed clients"
              help="The management platforms: prefixes, or hosts and prefixes by name. Empty: any client on those interfaces."
              :ui="inlineField"
            >
              <AddrInput v-model="form.snmp_allow" multiple placeholder="192.168.1.10/32" />
            </UFormField>
          </fieldset>

          <div v-if="!readOnly" class="mt-4">
            <UButton type="submit" :loading="saving" :disabled="!pageForm.dirty()">Save</UButton>
          </div>
        </form>
      </div>

      <CrudPage
        title="SNMPv3 users"
        description="Read-only users with their own passwords: authenticated (SHA) and, with privacy, encrypted (AES). Passwords are 8 to 64 characters."
        :api="snmpUsers"
        :params="{ instance_id: store.currentId }"
        :columns="userColumns"
        :fields="userFields"
        :defaults="userDefaults"
        noun="user"
        new-label="Add user"
        :item-name="(u) => `SNMPv3 user ${u.name}`"
      >
        <template #field-auth_password="{ form: f }">
          <UInput
            v-model="f.new_auth_password"
            type="password"
            autocomplete="new-password"
            class="w-full"
            :placeholder="f.has_auth_password ? 'set; leave empty to keep it' : ''"
          />
        </template>
        <template #field-priv_password="{ form: f }">
          <UInput
            v-model="f.new_priv_password"
            type="password"
            autocomplete="new-password"
            class="w-full"
            :placeholder="f.has_priv_password ? 'set; leave empty to keep it' : ''"
          />
        </template>
      </CrudPage>
    </div>
  </NeedInstance>
</template>
