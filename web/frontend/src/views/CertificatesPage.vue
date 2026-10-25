<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import TagsInput from '@/components/TagsInput.vue'
import { api, certificates, dyndnsClients } from '@/api'
import { errMsg } from '@/api/http'
import { useFormGuard } from '@/composables/useFormGuard'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { inlineField, wideModal } from '@/utils/form'
import { ago, when } from '@/utils/time'
import { useSearch, valuesText } from '@/utils/search'

const { store, ifaceItems, ifaceName } = useInstanceRefs()
const auth = useAuthStore()
const deploy = useDeployStore()
onMounted(() => deploy.refresh())

// The ACME CAs by name (fwconfig.ACMECAs).
const cas = ref([])
onMounted(async () => (cas.value = await api.acmeCAs()))
const caLabel = (name) => cas.value.find((c) => c.name === name)?.label ?? name

// The instance's DNS update clients, whose providers write DNS-01's TXT
// records.
const dnsClients = ref([])
watch(
  () => store.currentId,
  async (id) => (dnsClients.value = id ? await dyndnsClients.list({ instance_id: id }) : []),
  { immediate: true },
)
const dnsClientItems = computed(() =>
  dnsClients.value.map((c) => ({ label: `${c.name} (${c.zone})`, value: c.id })),
)
const dnsClientName = (id) => dnsClients.value.find((c) => c.id === id)?.name ?? ''

// What the agent reports for the instance's certificates, by name.
const states = computed(() => {
  const m = {}
  for (const s of deploy.status?.certificates ?? []) {
    if (s.instance === store.current?.name) m[s.name] = s
  }
  return m
})
const stateColor = { ok: 'success', error: 'error', expired: 'error', issuing: 'info' }
const imported = (row) => row.source === 'import'
// writable: the selected VF's certificates can be changed.
const writable = computed(() => auth.canEdit)

const route = useRoute()
const router = useRouter()
const toast = useToast()

// Store is the default tab; ?tab=overview or ?tab=cas opens another.
const tabs = [
  { label: 'Store', value: 'store', slot: 'store', icon: 'i-lucide-shield-check' },
  { label: 'Overview', value: 'overview', slot: 'overview', icon: 'i-lucide-list' },
  { label: 'Certificate authorities', value: 'cas', slot: 'cas', icon: 'i-lucide-landmark' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'store'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'store' ? undefined : v } }),
})

// The Store tab: the instance's certificates with what the agent holds.
const rows = ref([])
async function loadRows() {
  rows.value = store.currentId ? await certificates.list({ instance_id: store.currentId }) : []
}
watch([() => store.currentId, tab], loadRows, { immediate: true })
const { search, filtered } = useSearch(rows, (r) =>
  valuesText(r.name, r.domains, states.value[r.name]),
)

// lifetime is the share of the certificate's lifetime left (0..1), with
// the bar's colour: yellow under a third (when renewal is due), red under
// a quarter.
const now = ref(Date.now())
let timer
onMounted(() => (timer = setInterval(() => (now.value = Date.now()), 60_000)))
onUnmounted(() => clearInterval(timer))
function lifetime(st) {
  if (!st?.not_before || !st?.not_after) return null
  const from = Date.parse(st.not_before)
  const to = Date.parse(st.not_after)
  const left = Math.min(1, Math.max(0, (to - now.value) / (to - from)))
  const days = Math.max(0, Math.floor((to - now.value) / 86_400_000))
  const color = left < 1 / 4 ? 'bg-error' : left < 1 / 3 ? 'bg-warning' : 'bg-success'
  return { left, days, color }
}

const formats = [
  { label: 'PEM (certificate)', format: 'pem' },
  { label: 'PEM (full chain)', format: 'chain' },
  { label: 'DER (certificate)', format: 'der' },
]
// A CA's own certificate is what other hosts import to trust it.
const caFormats = [
  { label: 'Export CA, PEM', format: 'pem' },
  { label: 'Export CA, DER', format: 'der' },
]
const downloadItems = (row) =>
  (row.is_ca ? caFormats : formats).map((f) => ({
    label: f.label,
    onSelect: () => download(row, f.format),
  }))
// validity is where a row's dates are: the agent's for a deployed
// certificate, else the stored chain's (an imported one).
const validity = (row) =>
  states.value[row.name]?.not_after ? states.value[row.name] : row.not_after ? row : null
async function download(row, format) {
  try {
    const res = await api.certificateDownload(row.id, format)
    const name =
      /filename="([^"]+)"/.exec(res.headers['content-disposition'] ?? '')?.[1] ?? row.name
    const url = URL.createObjectURL(res.data)
    const a = document.createElement('a')
    a.href = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
  } catch (err) {
    let msg = errMsg(err)
    const data = err?.response?.data
    if (data instanceof Blob) {
      try {
        msg = JSON.parse(await data.text()).error ?? msg
      } catch {
        /* not JSON */
      }
    }
    toast.add({ title: msg, color: 'error' })
  }
}

// Import: a certificate with its key, from PEM files or pasted. A file's
// CERTIFICATE blocks go to the chain, a PRIVATE KEY block to the key, so
// one file may hold both.
const importOpen = ref(false)
const importSaving = ref(false)
const importForm = ref({})
const importGuard = useFormGuard(importForm, importOpen)
const fileInput = ref(null)
function openImport() {
  importForm.value = { name: '', description: '', enabled: true, fullchain: '', privkey: '' }
  importOpen.value = true
}
const pemBlocks = (text) =>
  text.match(/-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g) ?? []
async function loadFiles(e) {
  const certs = []
  let key = ''
  for (const file of e.target.files) {
    for (const b of pemBlocks(await file.text())) {
      if (b.startsWith('-----BEGIN CERTIFICATE-----')) certs.push(b)
      else if (/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(b)) key = b
    }
    if (!importForm.value.name) importForm.value.name = file.name.replace(/\.[^.]*$/, '')
  }
  e.target.value = ''
  if (!certs.length && !key) {
    toast.add({ title: 'No PEM certificate or private key in the file', color: 'error' })
    return
  }
  if (certs.length) importForm.value.fullchain = certs.join('\n') + '\n'
  if (key) importForm.value.privkey = key + '\n'
}
async function saveImport() {
  importSaving.value = true
  try {
    await certificates.create({
      ...importForm.value,
      instance_id: store.currentId,
      source: 'import',
    })
    importOpen.value = false
    toast.add({ title: `Certificate ${importForm.value.name} imported`, color: 'success' })
    await loadRows()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    importSaving.value = false
  }
}

// Create: portitor-web makes a key and a server certificate when it is
// saved, self-signed or signed by a CA of its firewall (global admins
// only), and stores them as an imported certificate.
const keyTypeItems = [
  { label: 'ECDSA P-256', value: 'ec256' },
  { label: 'ECDSA P-384', value: 'ec384' },
  { label: 'RSA 2048', value: 'rsa2048' },
  { label: 'RSA 3072', value: 'rsa3072' },
  { label: 'RSA 4096', value: 'rsa4096' },
]
// The firewall's CAs: imported certificates of its host that are CAs. They
// are deployed with the host, so they are kept on the firewall (on both
// hosts of an HA pair).
const host = computed(() => store.host)
const authorities = ref([])
async function loadCAs() {
  authorities.value = host.value
    ? (await certificates.list({ instance_id: host.value.id })).filter((r) => r.is_ca)
    : []
}
watch(() => host.value?.id, loadCAs, { immediate: true })
const issuerItems = computed(() => [
  { label: 'Self-signed', value: 0 },
  ...(auth.isAdmin
    ? authorities.value
        .filter((r) => r.has_privkey)
        .map((r) => ({ label: `${r.name} (${r.common_name})`, value: r.id }))
    : []),
])
const genOpen = ref(false)
const genSaving = ref(false)
const genForm = ref({})
const genGuard = useFormGuard(genForm, genOpen)
// openGenerate opens Create certificate, signed by the CA caID (0:
// self-signed), from the CA's row on the Certificate authorities tab.
async function openGenerate(caID = 0) {
  genForm.value = {
    name: '',
    description: '',
    enabled: true,
    domains: [],
    common_name: '',
    key_type: 'ec256',
    days: 825,
    ca_id: caID,
  }
  genOpen.value = true
  await loadCAs()
}
async function saveGenerate() {
  const { domains, common_name, key_type, days, ca_id, ...rest } = genForm.value
  genSaving.value = true
  try {
    await certificates.create({
      ...rest,
      instance_id: store.currentId,
      source: 'import',
      generate: { domains, common_name, key_type, days: Number(days), ca_id: ca_id || null },
    })
    genOpen.value = false
    toast.add({
      title: `Certificate ${rest.name} created in ${store.current?.name}`,
      color: 'success',
    })
    await loadRows()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    genSaving.value = false
  }
}

// The Certificate authorities tab: the firewall's CAs, on its host, made
// here or imported with their key. A new CA's gen_* fields go to the API as
// its generate request.
const caAPI = {
  ...certificates,
  list: async (params) => (await certificates.list(params)).filter((r) => r.is_ca),
  create: ({ mode, gen_common_name, gen_key_type, gen_days, ...body }) =>
    certificates
      .create({
        ...body,
        instance_id: host.value?.id,
        source: 'import',
        enabled: true,
        ...(mode === 'import'
          ? {}
          : {
              fullchain: '',
              privkey: '',
              generate: {
                ca: true,
                common_name: gen_common_name,
                key_type: gen_key_type,
                days: Number(gen_days),
              },
            }),
      })
      .finally(loadCAs),
  update: (id, body) => certificates.update(id, body).finally(loadCAs),
  remove: (id) => certificates.remove(id).finally(loadCAs),
}
const isNew = (form) => !form.id
const generating = (form) => isNew(form) && form.mode !== 'import'
const caColumns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'common_name', label: 'Common name' },
  { key: 'not_after', label: 'Valid' },
  { key: 'lifetime', label: 'Lifetime left' },
  { key: 'description', label: 'Description' },
  { key: 'actions', label: '' },
]
const caFields = [
  { key: 'name', label: 'Name', required: true, placeholder: 'internal-ca' },
  { key: 'description', label: 'Description' },
  {
    key: 'mode',
    label: 'Certificate',
    type: 'select',
    show: isNew,
    items: [
      { label: 'Create a new CA', value: 'generate' },
      { label: 'Import a CA with its key', value: 'import' },
    ],
  },
  {
    key: 'gen_common_name',
    label: 'Common name (CN)',
    show: generating,
    placeholder: 'the name',
    hint: "The CA's name, as clients show it. At most 64 characters.",
  },
  { key: 'gen_key_type', label: 'Key type', type: 'select', show: generating, items: keyTypeItems },
  {
    key: 'gen_days',
    label: 'Valid for (days)',
    type: 'number',
    show: generating,
    hint: 'The certificates it signs end no later than it does.',
  },
  {
    key: 'fullchain',
    label: 'Certificate (PEM)',
    type: 'textarea',
    show: (f) => !generating(f),
    hint: "The CA's certificate. A new one must match the key.",
  },
  {
    key: 'privkey',
    label: 'Private key (PEM)',
    type: 'textarea',
    show: (f) => !generating(f),
    hint: 'Signs the certificates. Leave empty to keep the stored key, which is never shown.',
  },
]

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'domains', label: 'SANs', class: 'font-mono', format: (r) => r.domains.join(', ') },
  {
    key: 'interface_id',
    label: 'Validation',
    format: (r) =>
      imported(r)
        ? ''
        : dns01(r)
          ? `DNS-01 · ${dnsClientName(r.dyndns_client_id)}`
          : `HTTP-01 · ${ifaceName(r.interface_id)}`,
  },
  {
    key: 'ca',
    label: 'CA',
    format: (r) => (imported(r) ? 'Imported' : caLabel(r.ca)),
  },
  { key: 'state', label: 'State' },
  { key: 'enabled', label: 'Enabled' },
]
const acme = (form) => form.source !== 'import'
const dns01 = (form) => acme(form) && form.challenge === 'dns-01'
const http01 = (form) => acme(form) && form.challenge !== 'dns-01'
const fields = computed(() => [
  { key: 'name', label: 'Name', required: true, placeholder: 'www' },
  { key: 'description', label: 'Description' },
  {
    key: 'fullchain',
    label: 'Certificate (PEM)',
    type: 'textarea',
    show: imported,
    hint: 'The certificate, then its intermediates. A new one must match the key.',
  },
  {
    key: 'privkey',
    label: 'Private key (PEM)',
    type: 'textarea',
    show: imported,
    hint: 'Leave empty to keep the stored key, which is never shown.',
  },
  {
    key: 'domains',
    show: acme,
    label: 'Subject Alternative Names (SANs)',
    type: 'tags',
    required: true,
    placeholder: 'www.example.com',
    hint: 'The DNS names in the certificate; clients check the name they connect to against these. With HTTP-01 each must resolve to an address of the interface below, and wildcards (*.example.com) need DNS-01.',
  },
  {
    key: 'common_name',
    show: acme,
    label: 'Common name (CN)',
    placeholder: 'the first SAN',
    hint: "Optional, at most 64 characters. Only shown to people inspecting the certificate: clients ignore the CN when matching names. Added to the SANs if missing. Let's Encrypt may leave it out.",
  },
  {
    key: 'challenge',
    show: acme,
    label: 'Challenge',
    type: 'select',
    items: [
      { label: 'HTTP-01 (port 80)', value: 'http-01' },
      { label: 'DNS-01 (TXT record)', value: 'dns-01' },
    ],
    hint: 'HTTP-01: the CA fetches a token from each name on port 80, so the names must be reachable from the Internet. DNS-01: the firewall puts a TXT record at _acme-challenge.<name> through a DNS update client, so internal names and wildcards work.',
  },
  {
    key: 'interface_id',
    show: http01,
    label: 'Interface',
    type: 'select',
    items: () => ifaceItems.value,
    required: true,
    hint: "Where the CA's HTTP-01 requests come in. Port 80 is opened on it only while a challenge is answered.",
  },
  {
    key: 'dyndns_client_id',
    show: dns01,
    label: 'DNS update client',
    type: 'select',
    items: () => dnsClientItems.value,
    required: true,
    hint: 'Its provider and credentials write the TXT records, in its zone. For a name outside that zone, add a CNAME from _acme-challenge.<name> to a name in it (_acme-challenge.www.example.com → www.acme.example.net): the firewall follows it. A client kept only for certificates can be disabled and needs no records.',
  },
  {
    key: 'email',
    show: acme,
    label: 'Email',
    placeholder: 'admin@example.com',
    hint: "The ACME account's contact. Optional.",
  },
  {
    key: 'ca',
    show: acme,
    label: 'CA',
    type: 'select',
    items: cas.value.map((c) => ({ label: c.label, value: c.name })),
    hint: 'Try the staging CA first: its test certificates are not trusted, but its rate limits are much higher.',
  },
  {
    key: 'key_type',
    show: acme,
    label: 'Key type',
    type: 'select',
    items: keyTypeItems,
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
])
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs">
      <template #store>
        <div class="space-y-3 pt-2">
          <div class="flex items-center gap-2">
            <SearchInput v-model="search" class="flex-1" />
            <UButton
              v-if="writable"
              icon="i-lucide-file-badge"
              color="neutral"
              variant="outline"
              label="Create certificate"
              @click="openGenerate()"
            />
            <UButton
              v-if="writable"
              icon="i-lucide-upload"
              label="Import certificate"
              @click="openImport"
            />
          </div>
          <table class="w-full text-sm">
            <thead class="text-left text-muted">
              <tr class="border-b border-default">
                <th class="py-1 pe-3 font-medium">Name</th>
                <th class="py-1 pe-3 font-medium">SANs</th>
                <th class="py-1 pe-3 font-medium">State</th>
                <th class="py-1 pe-3 font-medium">Valid</th>
                <th class="py-1 pe-3 font-medium min-w-48">Lifetime left</th>
                <th class="py-1 font-medium" />
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in filtered" :key="row.id" class="border-b border-default align-top">
                <td class="py-1 pe-3 font-medium">
                  {{ row.name }}
                  <div v-if="row.is_ca" class="text-xs text-muted">certificate authority</div>
                  <div v-else-if="imported(row)" class="text-xs text-muted">imported</div>
                  <div v-if="!row.enabled" class="text-xs text-muted">disabled</div>
                </td>
                <td class="py-1 pe-3 font-mono">{{ row.domains.join(', ') }}</td>
                <td class="py-1 pe-3 text-xs">
                  <template v-if="states[row.name]">
                    <UBadge
                      :color="stateColor[states[row.name].state] ?? 'neutral'"
                      variant="subtle"
                      size="sm"
                    >
                      {{ states[row.name].state }}
                    </UBadge>
                    <div v-if="states[row.name].issuer" class="text-muted">
                      {{ states[row.name].issuer }}
                    </div>
                    <div v-if="states[row.name].last_error" class="text-error">
                      {{ states[row.name].last_error }}
                    </div>
                  </template>
                  <template v-else>
                    <span class="text-muted">not deployed</span>
                    <div v-if="row.issuer" class="text-muted">{{ row.issuer }}</div>
                  </template>
                </td>
                <td class="py-1 pe-3 text-xs whitespace-nowrap">
                  <template v-if="validity(row)">
                    <div>from {{ when(validity(row).not_before) }}</div>
                    <div>until {{ when(validity(row).not_after) }}</div>
                  </template>
                </td>
                <td class="py-1 pe-3 text-xs">
                  <template v-if="lifetime(validity(row))">
                    <div class="h-2 w-full rounded bg-elevated overflow-hidden">
                      <div
                        class="h-full rounded"
                        :class="lifetime(validity(row)).color"
                        :style="{ width: lifetime(validity(row)).left * 100 + '%' }"
                      />
                    </div>
                    <div class="mt-0.5 text-muted">
                      {{ Math.round(lifetime(validity(row)).left * 100) }}% ·
                      {{ lifetime(validity(row)).days }} days
                    </div>
                  </template>
                  <span v-else class="text-muted">no certificate</span>
                </td>
                <td class="py-1 text-right">
                  <UDropdownMenu v-if="validity(row)" :items="downloadItems(row)">
                    <UButton
                      size="xs"
                      variant="outline"
                      color="neutral"
                      icon="i-lucide-download"
                      trailing-icon="i-lucide-chevron-down"
                      label="Download"
                    />
                  </UDropdownMenu>
                </td>
              </tr>
              <tr v-if="!filtered.length">
                <td colspan="6" class="py-4 text-center text-muted">No certificates</td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
      <template #overview>
        <CrudPage
          title="Certificates"
          noun="certificate"
          description="TLS certificates from Let's Encrypt (ACME), got by the firewall and renewed when two thirds of their lifetime have passed. The CA checks each domain over HTTP on port 80 (HTTP-01), which the firewall opens on the certificate's interface only while it answers, or by a TXT record the firewall writes through a DNS update client (DNS-01), which also works for internal names and wildcards. A certificate from elsewhere is imported with its key on the Store tab, and is never renewed. To serve the GUI itself with one, choose it under Settings → Portitor web."
          :api="certificates"
          :params="{ instance_id: store.currentId }"
          :columns="columns"
          :fields="fields"
          :defaults="{
            enabled: true,
            domains: [],
            ca: 'letsencrypt',
            key_type: 'ec256',
            challenge: 'http-01',
          }"
          new-label="New certificate"
          :search-text="(row) => valuesText(states[row.name])"
        >
          <template #cell-state="{ row }">
            <div v-if="states[row.name]" class="space-y-0.5 text-xs">
              <UBadge
                :color="stateColor[states[row.name].state] ?? 'neutral'"
                variant="subtle"
                size="sm"
              >
                {{ states[row.name].state }}
              </UBadge>
              <div v-if="states[row.name].not_after">
                valid until {{ when(states[row.name].not_after) }}
              </div>
              <div v-if="states[row.name].issuer" class="text-muted">
                {{ states[row.name].issuer }}
              </div>
              <div v-if="states[row.name].last_attempt" class="text-muted">
                ordered {{ ago(states[row.name].last_attempt) }}
              </div>
              <div v-if="states[row.name].last_error" class="text-error">
                {{ states[row.name].last_error }}
              </div>
              <div class="font-mono text-muted">{{ states[row.name].dir }}</div>
            </div>
            <span v-else class="text-xs text-muted">not deployed</span>
          </template>
        </CrudPage>
      </template>
      <template #cas>
        <CrudPage
          title="Certificate authorities"
          noun="certificate authority"
          :description="`The certificate authorities of firewall ${host?.name ?? ''}, kept on its host. They are deployed with the host like any imported certificate, so they are stored on the firewall itself (on both hosts of an HA pair), and sign the server certificates of the host and its virtual firewalls (Sign, or Create certificate on the Store tab). Export a CA and add it to the trust store of the hosts that should trust those certificates. Global admins manage them.`"
          :api="caAPI"
          :params="{ instance_id: host?.id }"
          shared
          :columns="caColumns"
          :fields="caFields"
          :defaults="{ mode: 'generate', gen_key_type: 'ec256', gen_days: 3650 }"
          :new-label="'New CA'"
          :search-text="(row) => valuesText(row.common_name)"
        >
          <template #cell-not_after="{ row }">
            <div v-if="row.not_after" class="text-xs whitespace-nowrap">
              <div>from {{ when(row.not_before) }}</div>
              <div>until {{ when(row.not_after) }}</div>
            </div>
          </template>
          <template #cell-lifetime="{ row }">
            <div v-if="lifetime(row)" class="min-w-40 text-xs">
              <div class="h-2 w-full rounded bg-elevated overflow-hidden">
                <div
                  class="h-full rounded"
                  :class="lifetime(row).color"
                  :style="{ width: lifetime(row).left * 100 + '%' }"
                />
              </div>
              <div class="mt-0.5 text-muted">
                {{ Math.round(lifetime(row).left * 100) }}% · {{ lifetime(row).days }} days
              </div>
            </div>
          </template>
          <template #cell-actions="{ row }">
            <div class="flex justify-end gap-1">
              <UButton
                v-if="auth.isAdmin && writable && row.has_privkey"
                size="xs"
                variant="outline"
                color="neutral"
                icon="i-lucide-signature"
                :label="`Sign for ${store.current?.name}`"
                @click="openGenerate(row.id)"
              />
              <UDropdownMenu :items="downloadItems(row)">
                <UButton
                  size="xs"
                  variant="outline"
                  color="neutral"
                  icon="i-lucide-share"
                  trailing-icon="i-lucide-chevron-down"
                  label="Export"
                />
              </UDropdownMenu>
            </div>
          </template>
        </CrudPage>
      </template>
    </UTabs>

    <UModal
      :open="importOpen"
      title="Import certificate"
      :ui="wideModal"
      :dismissible="false"
      @update:open="importGuard.onUpdateOpen"
    >
      <template #body>
        <form id="cert-import-form" class="space-y-3" @submit.prevent="saveImport">
          <p class="text-sm text-muted">
            A certificate with its private key, in PEM. It is stored on the firewall at the next
            commit and never renewed: import a new one before it expires.
          </p>
          <UFormField :ui="inlineField" label="Name" required>
            <UInput v-model="importForm.name" class="w-full" placeholder="www" required />
          </UFormField>
          <UFormField :ui="inlineField" label="Description">
            <UInput v-model="importForm.description" class="w-full" />
          </UFormField>
          <UFormField :ui="inlineField" label="Enabled">
            <USwitch v-model="importForm.enabled" />
          </UFormField>
          <UFormField
            :ui="inlineField"
            label="Files"
            help="PEM files with the certificate, its intermediates and the key; one file may hold them all."
          >
            <UButton
              icon="i-lucide-file-up"
              color="neutral"
              variant="outline"
              label="Load files…"
              @click="fileInput.click()"
            />
            <input
              ref="fileInput"
              type="file"
              multiple
              accept=".pem,.crt,.cer,.key,text/plain"
              hidden
              @change="loadFiles"
            />
          </UFormField>
          <UFormField
            :ui="inlineField"
            label="Certificate (PEM)"
            help="The certificate first, then its intermediates."
            required
          >
            <UTextarea
              v-model="importForm.fullchain"
              class="w-full font-mono"
              :rows="5"
              placeholder="-----BEGIN CERTIFICATE-----"
              required
            />
          </UFormField>
          <UFormField :ui="inlineField" label="Private key (PEM)" required>
            <UTextarea
              v-model="importForm.privkey"
              class="w-full font-mono"
              :rows="5"
              placeholder="-----BEGIN PRIVATE KEY-----"
              required
            />
          </UFormField>
        </form>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton color="neutral" variant="ghost" @click="importGuard.close">Cancel</UButton>
          <UButton type="submit" form="cert-import-form" :loading="importSaving">Import</UButton>
        </div>
      </template>
    </UModal>

    <UModal
      :open="genOpen"
      title="Create certificate"
      :ui="wideModal"
      :dismissible="false"
      @update:open="genGuard.onUpdateOpen"
    >
      <template #body>
        <form id="cert-gen-form" class="space-y-3" @submit.prevent="saveGenerate">
          <p class="text-sm text-muted">
            A new key and a server certificate for it in virtual firewall
            <strong>{{ store.current?.name }}</strong
            >, made now: self-signed, or signed by a certificate authority of its firewall. Clients
            trust it once it (or its CA) is in their trust store. It is stored like an imported
            certificate and never renewed: make a new one before it expires.
          </p>
          <UFormField :ui="inlineField" label="Name" required>
            <UInput v-model="genForm.name" class="w-full" placeholder="www" required />
          </UFormField>
          <UFormField :ui="inlineField" label="Description">
            <UInput v-model="genForm.description" class="w-full" />
          </UFormField>
          <UFormField :ui="inlineField" label="Enabled">
            <USwitch v-model="genForm.enabled" />
          </UFormField>
          <UFormField
            :ui="inlineField"
            label="Signed by"
            :help="
              auth.isAdmin
                ? 'A certificate authority of this firewall (the Certificate authorities tab), or the certificate\'s own key. A signed certificate ends no later than its CA.'
                : 'Only global admins sign with a certificate authority.'
            "
          >
            <USelect v-model="genForm.ca_id" :items="issuerItems" class="w-full" />
          </UFormField>
          <UFormField
            :ui="inlineField"
            label="Subject Alternative Names (SANs)"
            help="DNS names (wildcards too) and IP addresses; clients check the name or address they connect to against these."
            required
          >
            <TagsInput v-model="genForm.domains" placeholder="fw.example.com" />
          </UFormField>
          <UFormField
            :ui="inlineField"
            label="Common name (CN)"
            help="Optional, at most 64 characters; the first SAN when empty. A name or address is added to the SANs if missing."
          >
            <UInput v-model="genForm.common_name" class="w-full" placeholder="the first SAN" />
          </UFormField>
          <UFormField :ui="inlineField" label="Key type">
            <USelect v-model="genForm.key_type" :items="keyTypeItems" class="w-full" />
          </UFormField>
          <UFormField
            :ui="inlineField"
            label="Valid for (days)"
            help="Apple's systems refuse a server certificate valid for more than 825 days."
            required
          >
            <UInput
              v-model="genForm.days"
              type="number"
              min="1"
              max="36500"
              class="w-full"
              required
            />
          </UFormField>
        </form>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton color="neutral" variant="ghost" @click="genGuard.close">Cancel</UButton>
          <UButton type="submit" form="cert-gen-form" :loading="genSaving">Create</UButton>
        </div>
      </template>
    </UModal>
  </NeedInstance>
</template>
