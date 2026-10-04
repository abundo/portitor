<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref } from 'vue'
import CrudPage from '@/components/CrudPage.vue'
import { api, dyndnsClients } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'

// The form of a DNS update client (a dynamic zone's settings), opened by
// the page through openCreate/openEdit; its records are edited elsewhere.
const emit = defineEmits(['changed'])
const { store, ifaceItems } = useInstanceRefs()

// DNS hosting providers and their settings (fwconfig.DNSProviders).
const providers = ref([])
onMounted(async () => (providers.value = await api.dnsProviders()))
const RFC2136 = 'rfc2136'
const isRFC2136 = (f) => !f.provider || f.provider === RFC2136

// Saves send only the chosen provider's settings: switching provider in
// the form leaves the other one's in it.
function onlyProvider(body) {
  const fields = providers.value.find((p) => p.name === body.provider)?.fields ?? []
  const settings = {}
  for (const f of fields) settings[f.key] = body.provider_settings?.[f.key] ?? ''
  return { ...body, provider_settings: settings }
}
const clientApi = {
  ...dyndnsClients,
  create: (body) => dyndnsClients.create(onlyProvider(body)),
  update: (id, body) => dyndnsClients.update(id, onlyProvider(body)),
}

// One form row per provider setting, shown for its provider.
const providerFields = computed(() =>
  providers.value.flatMap((p) =>
    (p.fields ?? []).map((f) => ({
      key: `provider_${p.name}_${f.key}`,
      label: f.label,
      type: 'custom',
      required: f.required,
      hint: f.secret
        ? [f.hint, 'Stored on the server and never shown again.'].filter(Boolean).join(' ')
        : f.hint,
      show: (form) => form.provider === p.name,
      setting: f,
    })),
  ),
)
function settingPlaceholder(form, f) {
  if (f.secret && form.provider_secrets_set?.includes(f.key)) return 'stored; empty keeps it'
  return f.placeholder ?? ''
}

const algorithms = [
  'hmac-sha256',
  'hmac-sha512',
  'hmac-sha384',
  'hmac-sha224',
  'hmac-sha1',
  'hmac-md5',
]
const clientFields = computed(() => [
  { key: 'name', label: 'Name', required: true, placeholder: 'home' },
  { key: 'description', label: 'Description' },
  {
    key: 'interface_id',
    label: 'Interface',
    type: 'select',
    items: () => ifaceItems.value,
    required: true,
    hint: "A and AAAA records without a value get this interface's first global address.",
  },
  { key: 'zone', label: 'Zone', required: true, placeholder: 'example.com' },
  {
    key: 'provider',
    label: 'Provider',
    type: 'select',
    items: providers.value.map((p) => ({ label: p.label, value: p.name })),
    hint: 'RFC 2136 updates your own nameserver from this virtual firewall. A DNS hosting provider is updated through its API, called from the firewall host.',
  },
  ...providerFields.value,
  {
    key: 'server',
    label: 'Nameserver',
    required: true,
    placeholder: '192.0.2.53, [2001:db8::53]:53 or ns1.example.com',
    hint: "The zone's primary nameserver, by IP address or DNS name, optionally with a port. Updates are sent from this virtual firewall, and a name is looked up there.",
    show: isRFC2136,
  },
  {
    key: 'tsig_name',
    label: 'TSIG key name',
    placeholder: 'ddns-key.example.com',
    hint: 'Empty: updates are not signed.',
    show: isRFC2136,
  },
  {
    key: 'tsig_algorithm',
    label: 'TSIG algorithm',
    type: 'select',
    items: algorithms,
    show: (f) => isRFC2136(f) && !!f.tsig_name,
  },
  {
    key: 'tsig_secret',
    label: 'TSIG secret',
    type: 'password',
    placeholder: 'base64, as in the key file',
    hint: 'Stored on the server and never shown again. Leave empty to keep the stored secret.',
    show: (f) => isRFC2136(f) && !!f.tsig_name,
  },
  {
    key: 'retry_interval',
    label: 'Retry interval (seconds)',
    type: 'number',
    hint: 'Longest wait between retries after a failed update: the first is after 10 s, then twice as long each time. 0: 300.',
  },
  {
    key: 'verify_interval',
    label: 'Verify interval (seconds)',
    type: 'number',
    hint: 'How often records with a fixed value are checked. 0: 3600.',
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
])

const crud = ref(null)
defineExpose({
  openCreate: () => crud.value.openCreate(),
  openEdit: (client) => crud.value.openEdit(client),
  openView: (client) => crud.value.openView(client),
})
</script>

<template>
  <CrudPage
    ref="crud"
    form-only
    title="Dynamic zones"
    noun="dynamic zone"
    :item-name="(c) => `dynamic zone ${c.zone} (${c.name})`"
    :api="clientApi"
    :params="{ instance_id: store.currentId }"
    :columns="[]"
    :fields="clientFields"
    :defaults="{
      enabled: true,
      provider: 'rfc2136',
      provider_settings: {},
      tsig_algorithm: 'hmac-sha256',
      retry_interval: 0,
      verify_interval: 0,
    }"
    new-label=""
    @changed="emit('changed')"
  >
    <template v-for="pf in providerFields" :key="pf.key" #[`field-${pf.key}`]="{ form }">
      <UInput
        v-model="form.provider_settings[pf.setting.key]"
        :type="pf.setting.secret ? 'password' : 'text'"
        :placeholder="settingPlaceholder(form, pf.setting)"
        autocomplete="off"
        class="w-full"
      />
    </template>
  </CrudPage>
</template>
