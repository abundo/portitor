<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import AcmeProxyTab from '@/components/AcmeProxyTab.vue'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import TagsInput from '@/components/TagsInput.vue'
import { api } from '@/api'
import { certificatesOf, dnsUpdatesShallow } from '@/api/config'
import { errMsg } from '@/api/http'
import { useFormGuard } from '@/composables/useFormGuard'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { inlineField, wideModal } from '@/utils/form'
import { ago, when } from '@/utils/time'
import { useSearch, valuesText } from '@/utils/search'

const { store, ifaceNameItems, ifaceText } = useInstanceRefs()
// The certificates of the selected virtual firewall, and of its firewall's
// host (the CAs), in the configuration tree, by name.
const certificates = certificatesOf(() => store.currentName)
const hostCertificates = certificatesOf(() => store.host?.name)
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
  () => store.currentName,
  async (id) => (dnsClients.value = id ? await dnsUpdatesShallow.list() : []),
  { immediate: true },
)
const dnsClientItems = computed(() =>
  dnsClients.value.map((c) => ({ label: `${c.name} (${c.zone})`, value: c.name })),
)
const dnsClientName = (name) => name ?? ''

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

// Store is the default tab; ?tab=cas, ?tab=overview or ?tab=proxy opens another.
const tabs = [
  { label: 'Certificate store', value: 'store', slot: 'store', icon: 'i-lucide-shield-check' },
  { label: 'Certificate authorities', value: 'cas', slot: 'cas', icon: 'i-lucide-landmark' },
  { label: 'ACME certificates', value: 'overview', slot: 'overview', icon: 'i-lucide-list' },
  { label: 'ACME proxy', value: 'proxy', slot: 'proxy', icon: 'i-lucide-shield-plus' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'store'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'store' ? undefined : v } }),
})

// The Store tab: the instance's certificates with what the agent holds.
const rows = ref([])
async function loadRows() {
  rows.value = store.currentName ? await certificates.list() : []
}
watch([() => store.currentName, tab], loadRows, { immediate: true })
const { search, filtered } = useSearch(rows, (r) =>
  valuesText(r.name, r.domains, states.value[r.name]),
)

// The Store tab's tree: each certificate under its issuer, from the root
// CA down, by the certification path (chain, the certificate last) the
// agent read for a deployed one, else the stored chain's. An issuer that is
// not a certificate here (Let's Encrypt's, a CA of the firewall seen from a
// virtual firewall) is a node of its own. A certificate without a chain (an
// ACME one not got yet) is at the top.
const chainOf = (r) => states.value[r.name]?.chain ?? r.chain ?? null
const pathKey = (path) => JSON.stringify(path)
const tree = computed(() => {
  const nodes = new Map()
  const roots = []
  function node(path) {
    if (!path?.length) return null
    const key = pathKey(path)
    let n = nodes.get(key)
    if (!n) {
      n = { key, label: path.at(-1), row: null, children: [] }
      nodes.set(key, n)
      ;(node(path.slice(0, -1))?.children ?? roots).push(n)
    }
    return n
  }
  for (const r of rows.value) {
    const chain = chainOf(r)
    const n = node(chain)
    if (n && !n.row) n.row = r
    else
      (node(chain?.slice(0, -1))?.children ?? roots).push({
        key: `row-${r.id}`,
        row: r,
        children: [],
      })
  }
  const order = (a, b) =>
    !a.children.length - !b.children.length ||
    (a.row?.name ?? a.label).localeCompare(b.row?.name ?? b.label)
  const sort = (list) => list.sort(order).forEach((n) => sort(n.children))
  sort(roots)
  return roots
})
// The firewall's CAs by path, to name an issuer node that is one.
const authorityAt = computed(() => {
  const m = {}
  for (const a of authorities.value) if (a.chain) m[pathKey(a.chain)] = a
  return m
})
// The issuer nodes folded by the user; a search unfolds them all.
const folded = ref(new Set())
function toggleFold(key) {
  const s = new Set(folded.value)
  if (!s.delete(key)) s.add(key)
  folded.value = s
}
// treeRows is the tree as the table's rows, with each row's depth: while
// searching, the matches with the issuers above them.
const treeRows = computed(() => {
  const words = search.value.trim().toLowerCase()
  const match = new Set(filtered.value)
  const out = []
  function walk(list, depth) {
    for (const n of list) {
      const at = out.length
      const hit = n.row ? match.has(n.row) : !words || n.label.toLowerCase().includes(words)
      const open = words || !folded.value.has(n.key)
      out.push({ ...n, depth, open })
      if (open) walk(n.children, depth + 1)
      if (words && !hit && out.length === at + 1) out.pop()
    }
  }
  walk(tree.value, 0)
  return out
})

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
    const res = await (row._host ? hostCertificates : certificates).download(row.name, format)
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
// readPEM fills form's fullchain, privkey and (when empty) name from the
// files of the change event e.
async function readPEM(e, form) {
  const certs = []
  let key = ''
  for (const file of e.target.files) {
    for (const b of pemBlocks(await file.text())) {
      if (b.startsWith('-----BEGIN CERTIFICATE-----')) certs.push(b)
      else if (/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(b)) key = b
    }
    if (!form.name) form.name = file.name.replace(/\.[^.]*$/, '')
  }
  e.target.value = ''
  if (!certs.length && !key) {
    toast.add({ title: 'No PEM certificate or private key in the file', color: 'error' })
    return
  }
  if (certs.length) form.fullchain = certs.join('\n') + '\n'
  if (key) form.privkey = key + '\n'
}
const loadFiles = (e) => readPEM(e, importForm.value)
async function saveImport() {
  importSaving.value = true
  try {
    await certificates.create({ ...importForm.value, source: 'import' })
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
    ? (await hostCertificates.list()).filter((r) => r.is_ca).map((r) => ({ ...r, _host: true }))
    : []
}
watch(() => host.value?.id, loadCAs, { immediate: true })
const issuerItems = computed(() => [
  { label: 'Self-signed', value: 0 },
  ...(auth.isAdmin
    ? authorities.value
        .filter((r) => r.has_privkey)
        .map((r) => ({ label: `${r.name} (${r.common_name})`, value: r.name }))
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
      source: 'import',
      generate: { domains, common_name, key_type, days: Number(days), signed_by: ca_id || null },
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
  ...hostCertificates,
  list: async () =>
    (await hostCertificates.list()).filter((r) => r.is_ca).map((r) => ({ ...r, _host: true })),
  create: ({ mode, gen_common_name, gen_key_type, gen_days, ...body }) =>
    hostCertificates
      .create({
        ...body,
        source: 'import',
        enabled: true,
        ...(mode === 'import'
          ? { import_ca: true }
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
  update: (id, body) => hostCertificates.update(id, body).finally(loadCAs),
  remove: (id) => hostCertificates.remove(id).finally(loadCAs),
}
// caPage is the tab's CrudPage: Import CA opens its form in import mode.
const caPage = ref(null)
const caFileInput = ref(null)
const isNew = (form) => !form.id
const importing = (form) => isNew(form) && form.mode === 'import'
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
    key: 'files',
    label: 'Files',
    type: 'custom',
    show: importing,
    hint: "PEM files with the CA's certificate and its private key; one file may hold both.",
  },
  {
    key: 'fullchain',
    label: 'Certificate (PEM)',
    type: 'textarea',
    show: (f) => !generating(f),
    hint: "The CA's certificate (basic constraints CA:TRUE), then any CA above it. A new one must match the key.",
  },
  {
    key: 'privkey',
    label: 'Private key (PEM)',
    type: 'textarea',
    show: (f) => !generating(f),
    hint: 'Signs the certificates. Leave empty to keep the stored key, which is never shown.',
  },
]

// The Overview tab: the ACME client's certificates alone; imported and
// created ones are on the Store tab.
const acmeAPI = {
  ...certificates,
  list: async () => (await certificates.list()).filter((r) => !imported(r)),
}
const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'domains', label: 'SANs', class: 'font-mono', format: (r) => r.domains.join(', ') },
  {
    key: 'interface',
    label: 'Validation',
    format: (r) =>
      dns01(r) ? `DNS-01 · ${dnsClientName(r.dns_update)}` : `HTTP-01 · ${ifaceText(r.interface ?? '')}`,
  },
  { key: 'ca', label: 'CA', format: (r) => caLabel(r.ca) },
  { key: 'state', label: 'State' },
  { key: 'enabled', label: 'Enabled' },
]
// renew orders the certificate again now: a failed one without waiting
// for the next retry, a valid one before it is due.
async function renew(row) {
  try {
    await certificates.renew(row.name)
    toast.add({ title: `Ordering ${row.name}`, color: 'info' })
    setTimeout(() => deploy.refresh(), 2000)
  } catch (err) {
    toast.add({ title: errMsg(err, 'Renewal failed to start'), color: 'error' })
  }
}
const dns01 = (form) => form.challenge === 'dns-01'
const http01 = (form) => !dns01(form)
const fields = computed(() => [
  { key: 'name', label: 'Name', required: true, placeholder: 'www' },
  { key: 'description', label: 'Description' },
  {
    key: 'domains',
    label: 'Subject Alternative Names (SANs)',
    type: 'tags',
    required: true,
    placeholder: 'www.example.com',
    hint: 'The DNS names in the certificate; clients check the name they connect to against these. With HTTP-01 each must resolve to an address of the interface below, and wildcards (*.example.com) need DNS-01.',
  },
  {
    key: 'common_name',
    label: 'Common name (CN)',
    placeholder: 'the first SAN',
    hint: "Optional, at most 64 characters. Only shown to people inspecting the certificate: clients ignore the CN when matching names. Added to the SANs if missing. Let's Encrypt may leave it out.",
  },
  {
    key: 'challenge',
    label: 'Challenge',
    type: 'select',
    items: [
      { label: 'HTTP-01 (port 80)', value: 'http-01' },
      { label: 'DNS-01 (TXT record)', value: 'dns-01' },
    ],
    hint: 'HTTP-01: the CA fetches a token from each name on port 80, so the names must be reachable from the Internet. DNS-01: the firewall puts a TXT record at _acme-challenge.<name> through a DNS update client, so internal names and wildcards work.',
  },
  {
    key: 'interface',
    show: http01,
    label: 'Interface',
    type: 'select',
    items: () => ifaceNameItems.value,
    required: true,
    hint: "Where the CA's HTTP-01 requests come in. Port 80 is opened on it only while a challenge is answered.",
  },
  {
    key: 'dns_update',
    show: dns01,
    label: 'DNS update client',
    type: 'select',
    items: () => dnsClientItems.value,
    required: true,
    hint: 'Its provider and credentials write the TXT records, in its zone. For a name outside that zone, add a CNAME from _acme-challenge.<name> to a name in it (_acme-challenge.www.example.com → www.acme.example.net): the firewall follows it. A client kept only for certificates can be disabled and needs no records.',
  },
  {
    key: 'email',
    label: 'Email',
    placeholder: 'admin@example.com',
    hint: "The ACME account's contact. Optional.",
  },
  {
    key: 'ca',
    label: 'CA',
    type: 'select',
    items: cas.value.map((c) => ({ label: c.label, value: c.name })),
    hint: 'Try the staging CA first: its test certificates are not trusted, but its rate limits are much higher.',
  },
  {
    key: 'key_type',
    label: 'Key type',
    type: 'select',
    items: keyTypeItems,
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
])
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
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
              <tr
                v-for="node in treeRows"
                :key="node.key"
                class="border-b border-default align-top"
              >
                <td class="py-1 pe-3" :style="{ paddingInlineStart: `${node.depth * 1.5}rem` }">
                  <div class="flex items-start gap-1">
                    <UButton
                      v-if="node.children.length"
                      :icon="node.open ? 'i-lucide-chevron-down' : 'i-lucide-chevron-right'"
                      variant="ghost"
                      color="neutral"
                      size="xs"
                      class="-my-0.5 p-0.5"
                      :aria-label="node.open ? 'Fold' : 'Unfold'"
                      :disabled="!!search.trim()"
                      @click="toggleFold(node.key)"
                    />
                    <span v-else class="w-5 shrink-0" />
                    <UIcon
                      :name="
                        !node.row || node.row.is_ca ? 'i-lucide-landmark' : 'i-lucide-file-badge'
                      "
                      class="mt-0.5 size-4 shrink-0 text-muted"
                    />
                    <div v-if="node.row" class="font-medium">
                      {{ node.row.name }}
                      <div v-if="node.row.is_ca" class="text-xs font-normal text-muted">
                        certificate authority
                      </div>
                      <div v-else-if="imported(node.row)" class="text-xs font-normal text-muted">
                        imported
                      </div>
                      <div v-if="!node.row.enabled" class="text-xs font-normal text-muted">
                        disabled
                      </div>
                    </div>
                    <div v-else>
                      {{ authorityAt[node.key]?.name ?? node.label }}
                      <div class="text-xs text-muted">
                        {{
                          authorityAt[node.key]
                            ? `certificate authority of firewall ${host?.name ?? ''}`
                            : 'issuer'
                        }}
                      </div>
                    </div>
                  </div>
                </td>
                <td v-if="!node.row" colspan="5" />
                <template v-else>
                  <td class="py-1 pe-3 font-mono">{{ node.row.domains.join(', ') }}</td>
                  <td class="py-1 pe-3 text-xs">
                    <template v-if="states[node.row.name]">
                      <UBadge
                        :color="stateColor[states[node.row.name].state] ?? 'neutral'"
                        variant="subtle"
                        size="sm"
                      >
                        {{ states[node.row.name].state }}
                      </UBadge>
                      <div v-if="states[node.row.name].issuer" class="text-muted">
                        {{ states[node.row.name].issuer }}
                      </div>
                      <div v-if="states[node.row.name].last_error" class="text-error">
                        {{ states[node.row.name].last_error }}
                      </div>
                    </template>
                    <template v-else>
                      <span class="text-muted">not deployed</span>
                      <div v-if="node.row.issuer" class="text-muted">{{ node.row.issuer }}</div>
                    </template>
                  </td>
                  <td class="py-1 pe-3 text-xs whitespace-nowrap">
                    <template v-if="validity(node.row)">
                      <div>from {{ when(validity(node.row).not_before) }}</div>
                      <div>until {{ when(validity(node.row).not_after) }}</div>
                    </template>
                  </td>
                  <td class="py-1 pe-3 text-xs">
                    <template v-if="lifetime(validity(node.row))">
                      <div class="h-2 w-full rounded bg-elevated overflow-hidden">
                        <div
                          class="h-full rounded"
                          :class="lifetime(validity(node.row)).color"
                          :style="{ width: lifetime(validity(node.row)).left * 100 + '%' }"
                        />
                      </div>
                      <div class="mt-0.5 text-muted">
                        {{ Math.round(lifetime(validity(node.row)).left * 100) }}% ·
                        {{ lifetime(validity(node.row)).days }} days
                      </div>
                    </template>
                    <span v-else class="text-muted">no certificate</span>
                  </td>
                  <td class="py-1 text-right">
                    <UDropdownMenu v-if="validity(node.row)" :items="downloadItems(node.row)">
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
                </template>
              </tr>
              <tr v-if="!treeRows.length">
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
          description="TLS certificates from Let's Encrypt (ACME), got by the firewall and renewed when two thirds of their lifetime have passed. The CA checks each domain over HTTP on port 80 (HTTP-01), which the firewall opens on the certificate's interface only while it answers, or by a TXT record the firewall writes through a DNS update client (DNS-01), which also works for internal names and wildcards. A certificate from elsewhere is imported with its key on the Certificate store tab, and is never renewed. To serve the GUI itself with one, choose it under Settings → Portitor web."
          :api="acmeAPI"
          :params="{ _vf: store.currentName }"
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
          <template #row-actions="{ row }">
            <UButton
              v-if="
                writable && row.enabled && states[row.name] && states[row.name].state !== 'dry-run'
              "
              size="sm"
              variant="outline"
              color="neutral"
              icon="i-lucide-refresh-cw"
              label="Renew"
              title="Order the certificate again now"
              :loading="states[row.name].state === 'issuing'"
              @click="renew(row)"
            />
          </template>
        </CrudPage>
      </template>
      <template #cas>
        <CrudPage
          ref="caPage"
          title="Certificate authorities"
          noun="certificate authority"
          :description="`The certificate authorities of firewall ${host?.name ?? ''}, kept on its host. They are deployed with the host like any imported certificate, so they are stored on the firewall itself (on both hosts of an HA pair), and sign the server certificates of the host and its virtual firewalls (Sign, or Create certificate on the Certificate store tab). Export a CA and add it to the trust store of the hosts that should trust those certificates. Global admins manage them.`"
          :api="caAPI"
          :params="{ _vf: host?.id }"
          shared
          :columns="caColumns"
          :fields="caFields"
          :defaults="{ mode: 'generate', gen_key_type: 'ec256', gen_days: 3650 }"
          :new-label="'New CA'"
          :search-text="(row) => valuesText(row.common_name)"
        >
          <template #toolbar>
            <UButton
              v-if="auth.isAdmin && !auth.replica"
              icon="i-lucide-upload"
              color="neutral"
              variant="outline"
              label="Import CA"
              @click="caPage.openCreate({ mode: 'import' })"
            />
          </template>
          <template #field-files="{ form }">
            <UButton
              icon="i-lucide-file-up"
              color="neutral"
              variant="outline"
              label="Load files…"
              @click="caFileInput.click()"
            />
            <input
              ref="caFileInput"
              type="file"
              multiple
              accept=".pem,.crt,.cer,.key,text/plain"
              hidden
              @change="readPEM($event, form)"
            />
          </template>
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
      <template #proxy>
        <AcmeProxyTab />
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
