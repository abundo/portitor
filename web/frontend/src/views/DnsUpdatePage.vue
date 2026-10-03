<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { api, dyndnsClients, dyndnsRecords } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useDeployStore } from '@/stores/deploy'
import { ago } from '@/utils/time'
import { valuesText } from '@/utils/search'

const { store, ifaceItems, ifaceName } = useInstanceRefs()
const deploy = useDeployStore()
onMounted(() => deploy.refresh())

// DNS hosting providers and their settings (fwconfig.DNSProviders).
const providers = ref([])
onMounted(async () => (providers.value = await api.dnsProviders()))
const RFC2136 = 'rfc2136'
const isRFC2136 = (f) => !f.provider || f.provider === RFC2136
const providerLabel = (name) =>
  providers.value.find((p) => p.name === (name || RFC2136))?.label ?? name

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

const clients = ref([])
const selectedId = ref(null)
async function loadClients() {
  if (!store.currentId) return
  clients.value = await dyndnsClients.list({ instance_id: store.currentId })
  if (!clients.value.some((c) => c.id === selectedId.value))
    selectedId.value = clients.value[0]?.id ?? null
}
watch(() => store.currentId, loadClients, { immediate: true })
const selected = computed(() => clients.value.find((c) => c.id === selectedId.value))
const clientItems = computed(() => clients.value.map((c) => ({ label: c.name, value: c.id })))

// What the agent reports for the instance's clients, by name.
const states = computed(() => {
  const m = {}
  for (const s of deploy.status?.dyndns ?? []) {
    if (s.instance === store.current?.name) m[s.name] = s
  }
  return m
})
const stateColor = { ok: 'success', error: 'error', waiting: 'warning' }

const clientColumns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'interface_id', label: 'Interface', format: (r) => ifaceName(r.interface_id) },
  { key: 'zone', label: 'Zone', class: 'font-mono' },
  {
    key: 'server',
    label: 'Provider',
    format: (r) => (isRFC2136(r) ? r.server : providerLabel(r.provider)),
  },
  { key: 'state', label: 'State' },
  { key: 'enabled', label: 'Enabled' },
]
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

const recordColumns = [
  { key: 'name', label: 'Name', class: 'font-mono' },
  { key: 'type', label: 'Type' },
  {
    key: 'value',
    label: 'Value',
    class: 'font-mono',
    format: (r) =>
      r.value ||
      { A: 'interface IPv4', AAAA: 'interface IPv6', TXT: 'time of last update' }[r.type] ||
      '',
  },
  { key: 'ttl', label: 'TTL', format: (r) => r.ttl || 300 },
  { key: 'description', label: 'Description' },
]
const recordFields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'home, @ or home.example.com.',
    hint: 'Relative to the zone; @ is the zone itself.',
  },
  { key: 'type', label: 'Type', type: 'select', items: ['A', 'AAAA', 'CNAME', 'TXT'] },
  {
    key: 'value',
    label: 'Value',
    placeholder: 'empty: follow the interface',
    hint: 'A/AAAA: empty follows the interface, an address is fixed. CNAME: the target. TXT: the text; empty holds the time of the last update.',
  },
  { key: 'ttl', label: 'TTL (seconds)', type: 'number', hint: '0: 300.' },
  { key: 'description', label: 'Description' },
]
</script>

<template>
  <NeedInstance>
    <div class="space-y-4">
      <CrudPage
        title="DNS update"
        noun="DNS update client"
        description="Keep DNS records in step with an interface's addresses: on your own nameserver by RFC 2136 dynamic update (TSIG signed), or at a DNS hosting provider through its API. Records are checked when the addresses change and updated only when they differ."
        :api="clientApi"
        :params="{ instance_id: store.currentId }"
        :columns="clientColumns"
        :fields="clientFields"
        :defaults="{
          enabled: true,
          provider: 'rfc2136',
          provider_settings: {},
          tsig_algorithm: 'hmac-sha256',
          retry_interval: 0,
          verify_interval: 0,
        }"
        new-label="New client"
        :search-text="(row) => valuesText(states[row.name])"
        @changed="loadClients"
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
        <template #cell-state="{ row }">
          <div v-if="states[row.name]" class="space-y-0.5 text-xs">
            <UBadge
              :color="stateColor[states[row.name].state] ?? 'neutral'"
              variant="subtle"
              size="sm"
            >
              {{ states[row.name].state }}
            </UBadge>
            <div v-if="states[row.name].ipv4 || states[row.name].ipv6" class="font-mono">
              {{ [states[row.name].ipv4, states[row.name].ipv6].filter(Boolean).join(', ') }}
            </div>
            <div v-if="states[row.name].server" class="font-mono text-muted">
              nameserver {{ states[row.name].server }}
            </div>
            <div class="text-muted">updated {{ ago(states[row.name].last_update) }}</div>
            <div v-if="states[row.name].last_error" class="text-error">
              {{ states[row.name].last_error }}
            </div>
          </div>
          <span v-else class="text-xs text-muted">not deployed</span>
        </template>
      </CrudPage>

      <div v-if="clients.length" class="card flex items-center gap-3">
        <span class="text-sm text-muted">Records of</span>
        <USelect v-model="selectedId" :items="clientItems" class="w-40" />
        <span v-if="selected" class="font-mono text-sm">{{ selected.zone }}</span>
      </div>
      <CrudPage
        v-if="selected"
        :key="selected.id"
        :title="`Records of ${selected.name}`"
        noun="record"
        description="One record per name and type; an update replaces the whole RRset. A name with a CNAME can have no other records."
        :api="dyndnsRecords"
        :params="{ client_id: selected.id }"
        :columns="recordColumns"
        :fields="recordFields"
        :defaults="{ type: 'A', ttl: 0 }"
        new-label="New record"
        :item-name="(r) => `record ${r.name} ${r.type}`"
      />
    </div>
  </NeedInstance>
</template>
