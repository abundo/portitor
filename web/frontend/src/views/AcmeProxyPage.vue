<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- The ACME proxy: an ACME server for the hosts behind the firewall,
     which gets their certificates from Let's Encrypt by DNS-01 or
     HTTP-01. Its settings and interfaces, its policies, and what it has
     issued. -->
<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import CrudPage from '@/components/CrudPage.vue'
import FormHeader from '@/components/FormHeader.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { acmeProxyPolicies, api, certificates, dyndnsClients, instances, interfaces } from '@/api'
import { errMsg } from '@/api/http'
import { useStatusRefresh } from '@/composables/useAutoRefresh'
import { withLabel } from '@/composables/useInstanceRefs'
import { usePageForm } from '@/composables/useFormGuard'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { useInstanceStore } from '@/stores/instances'
import { inlineField } from '@/utils/form'
import { useSearch } from '@/utils/search'
import { when } from '@/utils/time'

const toast = useToast()
const auth = useAuthStore()
const store = useInstanceStore()
const deploy = useDeployStore()
const readOnly = computed(() => !auth.canEdit)
const { auto, loading } = useStatusRefresh()

const cas = ref([])
onMounted(async () => (cas.value = await api.acmeCAs()))
const caItems = computed(() => cas.value.map((c) => ({ label: c.label, value: c.name })))

// The instance's certificates (the one the server presents), DNS update
// clients and interfaces (the policies' DNS-01 and HTTP-01).
const certs = ref([])
const dnsClients = ref([])
const ifaceRows = ref([])
const SELF = 0 // the self-signed certificate, null in the database
const certItems = computed(() => [
  { label: 'Self-signed (made by the firewall)', value: SELF },
  ...certs.value.filter((c) => !c.is_ca).map((c) => ({ label: c.name, value: c.id })),
])
const dnsClientItems = computed(() =>
  dnsClients.value.map((c) => ({ label: `${c.name} (${c.zone})`, value: c.id })),
)
const dnsClientName = (id) => dnsClients.value.find((c) => c.id === id)?.name ?? ''
const ifaceItems = computed(() =>
  ifaceRows.value.map((i) => ({ label: withLabel(i.label, i.name), value: i.id })),
)
const ifaceText = (id) => {
  const i = ifaceRows.value.find((x) => x.id === id)
  return i ? withLabel(i.label, i.name) : ''
}

// The instance's acme_proxy_* fields, and its interfaces' acme_proxy_serve.
const form = reactive({
  acme_proxy_enabled: false,
  acme_proxy_port: 8555,
  acme_proxy_ca: 'letsencrypt',
  acme_proxy_email: '',
  acme_proxy_certificate_id: SELF,
  ifaces: [], // { id, name, label, description, addresses, acme_proxy_serve }
})
const pageForm = usePageForm(form)
const saving = ref(false)
let loaded = []

async function load() {
  const id = store.currentId
  if (!id) return
  const [inst, ifs, cs, dcs] = await Promise.all([
    instances.get(id),
    interfaces.list({ instance_id: id }),
    certificates.list({ instance_id: id }),
    dyndnsClients.list({ instance_id: id }),
  ])
  loaded = ifs
  ifaceRows.value = ifs
  certs.value = cs
  dnsClients.value = dcs
  Object.assign(form, {
    acme_proxy_enabled: inst.acme_proxy_enabled ?? false,
    acme_proxy_port: inst.acme_proxy_port || 8555,
    acme_proxy_ca: inst.acme_proxy_ca || 'letsencrypt',
    acme_proxy_email: inst.acme_proxy_email ?? '',
    acme_proxy_certificate_id: inst.acme_proxy_certificate_id ?? SELF,
    ifaces: ifs.map((i) => ({
      id: i.id,
      name: i.name,
      label: i.label,
      description: i.description,
      addresses: i.addresses ?? [],
      acme_proxy_serve: i.acme_proxy_serve ?? false,
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
    const { ifaces, ...proxy } = form
    proxy.acme_proxy_port = Number(proxy.acme_proxy_port)
    if (proxy.acme_proxy_certificate_id === SELF) proxy.acme_proxy_certificate_id = null
    await instances.update(store.currentId, proxy)
    for (const i of ifaces) {
      const o = loaded.find((x) => x.id === i.id)
      if (o && !!o.acme_proxy_serve !== i.acme_proxy_serve)
        await interfaces.update(i.id, { acme_proxy_serve: i.acme_proxy_serve })
    }
    toast.add({ title: 'ACME proxy saved; commit to apply it.', color: 'success' })
    await Promise.all([load(), store.load()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}

// What the agent reports for this instance's proxy.
const status = computed(() =>
  (deploy.status?.acme_proxy ?? []).find((p) => p.instance === store.current?.name),
)
const stateColor = { running: 'success', error: 'error' }
// The directory URLs on the serving interfaces' static addresses.
const directories = computed(() => {
  const port = status.value?.port ?? form.acme_proxy_port
  const out = []
  for (const i of form.ifaces) {
    if (!i.acme_proxy_serve) continue
    for (const a of i.addresses) {
      const addr = a.split('/')[0]
      if (!/^[0-9a-f.:]+$/i.test(addr)) continue
      out.push(`https://${addr.includes(':') ? `[${addr}]` : addr}:${port}/directory`)
    }
  }
  return out
})
function downloadSelfSigned() {
  const url = URL.createObjectURL(
    new Blob([status.value.self_signed], { type: 'application/x-pem-file' }),
  )
  const a = document.createElement('a')
  a.href = url
  a.download = `acme-proxy-${store.current?.name ?? 'ca'}.pem`
  a.click()
  URL.revokeObjectURL(url)
}

const issued = computed(() => status.value?.issued ?? [])
const { search: issuedSearch, filtered: shownIssued } = useSearch(
  issued,
  (e) => `${e.client} ${e.names.join(' ')} ${e.issuer ?? ''} ${e.error ?? ''}`,
)

// ----- policies.
const policyColumns = [
  { key: 'name', label: 'Policy', class: 'font-medium' },
  { key: 'domains', label: 'Names', class: 'font-mono', format: (p) => p.domains.join(', ') },
  {
    key: 'sources',
    label: 'Clients',
    class: 'font-mono',
    format: (p) => (p.sources.length ? p.sources.join(', ') : 'any'),
  },
  {
    key: 'challenge',
    label: 'Upstream',
    format: (p) =>
      p.challenge === 'http-01'
        ? `HTTP-01 on ${ifaceText(p.interface_id)}`
        : `DNS-01 by ${dnsClientName(p.dyndns_client_id)}`,
  },
  { key: 'enabled', label: 'Enabled' },
  { key: 'description', label: 'Description' },
]
const policyFields = computed(() => [
  { key: 'name', label: 'Name', required: true, placeholder: 'servers' },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
  {
    key: 'domains',
    label: 'Names',
    type: 'tags',
    placeholder: '*.lan.example.com',
    hint: 'The names a client may get a certificate for: host.example.com allows that name, *.example.com any name below example.com (not example.com itself). Wildcard certificates can’t be asked for: the proxy checks each name by HTTP-01.',
  },
  {
    key: 'sources',
    label: 'Clients',
    type: 'addrs',
    placeholder: '192.168.1.0/24',
    hint: 'The hosts that may ask, as prefixes or hosts and prefixes by name. Every address a name resolves to must be in them too. Empty: any host that can reach the proxy.',
  },
  {
    key: 'challenge',
    label: 'Upstream challenge',
    type: 'select',
    items: [
      { label: 'DNS-01 (TXT record)', value: 'dns-01' },
      { label: 'HTTP-01 (port 80)', value: 'http-01' },
    ],
    hint: 'How Let’s Encrypt checks the names for the firewall. DNS-01: the firewall writes a TXT record through a DNS update client, so the names need not be reachable from the Internet. HTTP-01: the firewall answers on port 80 itself, so the names must resolve to it from the Internet (internal DNS may still give the clients’ own addresses). The names of one order must use the same challenge.',
  },
  {
    key: 'dyndns_client_id',
    show: (form) => form.challenge !== 'http-01',
    label: 'DNS update client',
    type: 'select',
    items: () => dnsClientItems.value,
    required: true,
    hint: 'Writes the TXT records of the DNS-01 challenge at Let’s Encrypt, as for a DNS-01 certificate: in its zone, following a CNAME at _acme-challenge.<name>.',
  },
  {
    key: 'interface_id',
    show: (form) => form.challenge === 'http-01',
    label: 'Interface',
    type: 'select',
    items: () => ifaceItems.value,
    required: true,
    hint: 'Where Let’s Encrypt’s HTTP-01 requests come in. Port 80 is opened on it only while a challenge is answered, as for an HTTP-01 certificate; it must not be forwarded elsewhere.',
  },
])
</script>

<template>
  <NeedInstance>
    <div class="space-y-4">
      <div class="card">
        <form @submit.prevent="save">
          <FormHeader title="ACME proxy">
            <UButton v-if="!readOnly" type="submit" :loading="saving" :disabled="!pageForm.dirty()"
              >Save</UButton
            >
          </FormHeader>
          <p class="mb-4 text-sm text-muted">
            An ACME server for the hosts behind the firewall. Point certbot, Caddy, Traefik or
            another ACME client at its directory URL: it proves control of a name over the internal
            network (HTTP-01, which the firewall checks from this virtual firewall), and the
            firewall gets the certificate from Let's Encrypt, by DNS-01 or by HTTP-01 answered on
            the firewall itself, as each policy says. Only the firewall holds the DNS credentials
            and the ACME account, and the hosts need not be reachable from the Internet. Policies
            decide which hosts may ask for which names.
          </p>
          <fieldset :disabled="readOnly" class="space-y-3">
            <UFormField label="Enabled" :ui="inlineField">
              <USwitch v-model="form.acme_proxy_enabled" />
            </UFormField>
            <UFormField label="Port" help="HTTPS, on the interfaces below." :ui="inlineField">
              <UInput v-model="form.acme_proxy_port" type="number" min="1" max="65535" />
            </UFormField>
            <UFormField
              label="Server certificate"
              help="What the proxy presents to its clients. Self-signed: download it below and have the clients trust it (certbot: REQUESTS_CA_BUNDLE; lego and Traefik: LEGO_CA_CERTIFICATES)."
              :ui="inlineField"
            >
              <USelect v-model="form.acme_proxy_certificate_id" :items="certItems" class="w-full" />
            </UFormField>
            <UFormField
              label="CA"
              help="Where the certificates come from. Try the staging CA first."
              :ui="inlineField"
            >
              <USelect v-model="form.acme_proxy_ca" :items="caItems" class="w-full" />
            </UFormField>
            <UFormField
              label="Email"
              help="The upstream ACME account's contact. Optional."
              :ui="inlineField"
            >
              <UInput
                v-model="form.acme_proxy_email"
                class="w-full"
                placeholder="admin@example.com"
              />
            </UFormField>
          </fieldset>

          <h2 class="border-b border-default pb-1 mt-8 mb-2 text-xl font-semibold">
            Answering clients
          </h2>
          <p class="mb-4 text-sm text-muted">
            The proxy answers on the interfaces turned on here, from the policies' clients.
          </p>
          <div class="mb-2">
            <SearchInput v-model="ifaceSearch" />
          </div>
          <fieldset :disabled="readOnly" class="min-w-0 overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-default text-left text-xs text-muted">
                  <th class="py-1 pr-4 font-medium">Interface</th>
                  <th class="pr-4 font-medium">Description</th>
                  <th class="pr-4 font-medium">Answer ACME clients</th>
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
                    <USwitch
                      v-model="i.acme_proxy_serve"
                      :aria-label="`Answer ACME clients on ${i.name}`"
                    />
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
        </form>
      </div>

      <CrudPage
        title="Policies"
        description="Which hosts may get certificates for which names, and how the firewall answers Let's Encrypt for them: by DNS-01 through a DNS update client, or by HTTP-01 on an interface. A name is looked up in the policies by name order; the first that allows it from the client is used."
        :api="acmeProxyPolicies"
        :params="{ instance_id: store.currentId }"
        :columns="policyColumns"
        :fields="policyFields"
        :defaults="{ enabled: true, domains: [], sources: [], challenge: 'dns-01' }"
        noun="policy"
        new-label="Add policy"
        :item-name="(p) => `policy ${p.name}`"
      />

      <div class="card">
        <div
          class="flex flex-wrap items-center justify-between gap-2 border-b border-default pb-1 mb-2"
        >
          <h2 class="text-xl font-semibold">Status</h2>
          <AutoRefreshButton :auto="auto" :loading="loading" />
        </div>
        <div v-if="!status" class="text-sm text-muted">
          Not running: enable it, add a policy and an interface, and commit.
        </div>
        <div v-else class="space-y-3 text-sm">
          <div class="flex flex-wrap items-center gap-2">
            <UBadge :color="stateColor[status.state] ?? 'neutral'" variant="subtle">
              {{ status.state }}
            </UBadge>
            <span v-if="status.last_error" class="text-error">{{ status.last_error }}</span>
          </div>
          <div v-if="directories.length">
            <div class="text-xs text-muted">Directory URL</div>
            <div v-for="d in directories" :key="d" class="font-mono select-all">{{ d }}</div>
          </div>
          <div v-if="status.self_signed">
            <UButton
              size="sm"
              variant="outline"
              color="neutral"
              icon="i-lucide-download"
              label="Download the self-signed certificate"
              @click="downloadSelfSigned"
            />
          </div>

          <h3 class="pt-2 font-semibold">Issued</h3>
          <SearchInput v-model="issuedSearch" />
          <div class="min-w-0 overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-default text-left text-xs text-muted">
                  <th class="py-1 pr-4 font-medium">Time</th>
                  <th class="pr-4 font-medium">Client</th>
                  <th class="pr-4 font-medium">Names</th>
                  <th class="pr-4 font-medium">Result</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(e, n) in shownIssued"
                  :key="n"
                  class="border-b border-default last:border-0 align-top"
                >
                  <td class="py-1 pr-4 whitespace-nowrap">{{ when(e.time) }}</td>
                  <td class="py-1 pr-4 font-mono">{{ e.client }}</td>
                  <td class="py-1 pr-4 font-mono">{{ e.names.join(', ') }}</td>
                  <td class="py-1 pr-4 text-xs">
                    <span v-if="e.error" class="text-error">{{ e.error }}</span>
                    <template v-else>
                      valid until {{ when(e.not_after) }}
                      <div class="text-muted">{{ e.issuer }}</div>
                    </template>
                  </td>
                </tr>
                <tr v-if="!shownIssued.length">
                  <td colspan="4" class="py-2 text-muted">
                    {{ issued.length ? 'Nothing matches.' : 'No certificates yet.' }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </NeedInstance>
</template>
