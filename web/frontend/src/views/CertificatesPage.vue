<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { api, certificates } from '@/api'
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

const route = useRoute()
const router = useRouter()
const toast = useToast()

// Store is the default tab; ?tab=overview opens the other.
const tabs = [
  { label: 'Store', value: 'store', slot: 'store', icon: 'i-lucide-shield-check' },
  { label: 'Overview', value: 'overview', slot: 'overview', icon: 'i-lucide-list' },
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
const downloadItems = (row) =>
  formats.map((f) => ({ label: f.label, onSelect: () => download(row, f.format) }))
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

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'domains', label: 'SANs', class: 'font-mono', format: (r) => r.domains.join(', ') },
  {
    key: 'interface_id',
    label: 'Interface',
    format: (r) => (imported(r) ? '' : ifaceName(r.interface_id)),
  },
  { key: 'ca', label: 'CA', format: (r) => (imported(r) ? 'Imported' : caLabel(r.ca)) },
  { key: 'state', label: 'State' },
  { key: 'enabled', label: 'Enabled' },
]
const acme = (form) => form.source !== 'import'
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
    hint: 'The DNS names in the certificate; clients check the name they connect to against these. Each must resolve to an address of the interface below. No wildcards.',
  },
  {
    key: 'common_name',
    show: acme,
    label: 'Common name (CN)',
    placeholder: 'the first SAN',
    hint: "Optional, at most 64 characters. Only shown to people inspecting the certificate: clients ignore the CN when matching names. Added to the SANs if missing. Let's Encrypt may leave it out.",
  },
  {
    key: 'interface_id',
    show: acme,
    label: 'Interface',
    type: 'select',
    items: () => ifaceItems.value,
    required: true,
    hint: "Where the CA's HTTP-01 requests come in. Port 80 is opened on it only while a challenge is answered.",
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
    items: [
      { label: 'ECDSA P-256', value: 'ec256' },
      { label: 'ECDSA P-384', value: 'ec384' },
      { label: 'RSA 2048', value: 'rsa2048' },
      { label: 'RSA 3072', value: 'rsa3072' },
      { label: 'RSA 4096', value: 'rsa4096' },
    ],
  },
  {
    key: 'challenge',
    show: acme,
    label: 'Challenge',
    type: 'select',
    items: [{ label: 'HTTP-01 (port 80)', value: 'http-01' }],
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
              v-if="auth.canEdit"
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
                  <div v-if="imported(row)" class="text-xs text-muted">imported</div>
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
                  <span v-else class="text-muted">not deployed</span>
                </td>
                <td class="py-1 pe-3 text-xs whitespace-nowrap">
                  <template v-if="states[row.name]?.not_after">
                    <div>from {{ when(states[row.name].not_before) }}</div>
                    <div>until {{ when(states[row.name].not_after) }}</div>
                  </template>
                </td>
                <td class="py-1 pe-3 text-xs">
                  <template v-if="lifetime(states[row.name])">
                    <div class="h-2 w-full rounded bg-elevated overflow-hidden">
                      <div
                        class="h-full rounded"
                        :class="lifetime(states[row.name]).color"
                        :style="{ width: lifetime(states[row.name]).left * 100 + '%' }"
                      />
                    </div>
                    <div class="mt-0.5 text-muted">
                      {{ Math.round(lifetime(states[row.name]).left * 100) }}% ·
                      {{ lifetime(states[row.name]).days }} days
                    </div>
                  </template>
                  <span v-else class="text-muted">no certificate</span>
                </td>
                <td class="py-1 text-right">
                  <UDropdownMenu v-if="states[row.name]?.not_after" :items="downloadItems(row)">
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
          description="TLS certificates from Let's Encrypt (ACME), got by the firewall and renewed when two thirds of their lifetime have passed. The CA checks each domain over HTTP on port 80, which the firewall opens on the certificate's interface only while it answers. A certificate from elsewhere is imported with its key on the Store tab, and is never renewed. To serve the GUI itself with one, choose it under Settings → Portitor web."
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
  </NeedInstance>
</template>
