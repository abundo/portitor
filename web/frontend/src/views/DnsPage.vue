<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import TagsInput from '@/components/TagsInput.vue'
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import AddrInput from '@/components/AddrInput.vue'
import CrudPage from '@/components/CrudPage.vue'
import DnsTemplates from '@/components/DnsTemplates.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { dnsTemplates, dnsZones, instances, interfaces } from '@/api'
import { errMsg } from '@/api/http'
import { withLabel } from '@/composables/useInstanceRefs'
import { usePageForm } from '@/composables/useFormGuard'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { zoneTypes } from '@/utils/dns'
import { inlineField } from '@/utils/form'
import { useSearch } from '@/utils/search'

const toast = useToast()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const store = useInstanceStore()
const readOnly = computed(() => !auth.canEdit)
const templates = ref([])

// The DNS templates a zone can use: the instance's own and the global ones.
async function loadTemplates() {
  const id = store.currentId
  templates.value = (await dnsTemplates.list()).filter((t) => t.instance_id === id || t.global)
}
watch(() => store.currentId, loadTemplates, { immediate: true })

// The DNS server: the instance's dns_* fields, and per interface whether
// BIND answers on it and whether its DHCP lease gives the upstream servers.
const upstreams = [
  { label: 'Forward to DNS servers', value: 'forward' },
  { label: 'DNS servers from the DHCP lease on an interface', value: 'dhcp' },
  { label: 'Root servers (resolve itself)', value: 'root' },
]
const server = reactive({
  dns_upstream: 'root',
  dns_forwarders: [],
  dns_forward_mode: 'first',
  dns_allow_recursion: [],
  dns_dnssec_validation: 'auto',
  dns_query_log: false,
  dns_query_log_clients: [],
  dns_query_log_names: [],
  dns_query_log_types: [],
  ifaces: [], // { id, name, label, description, ipv4_mode, dns_listen, dns_from_dhcp }
})
const serverForm = usePageForm(server)
const saving = ref(false)
let loaded = null // the rows as loaded, to save only what changed

async function load() {
  const id = store.currentId
  if (!id) return
  const [inst, ifs] = await Promise.all([instances.get(id), interfaces.list({ instance_id: id })])
  loaded = { inst, ifs }
  Object.assign(server, {
    dns_upstream: inst.dns_upstream || 'root',
    dns_forwarders: inst.dns_forwarders ?? [],
    dns_forward_mode: inst.dns_forward_mode || 'first',
    dns_allow_recursion: inst.dns_allow_recursion ?? [],
    dns_dnssec_validation: inst.dns_dnssec_validation || 'auto',
    dns_query_log: inst.dns_query_log ?? false,
    dns_query_log_clients: inst.dns_query_log_clients ?? [],
    dns_query_log_names: inst.dns_query_log_names ?? [],
    dns_query_log_types: inst.dns_query_log_types ?? [],
    ifaces: ifs.map((i) => ({
      id: i.id,
      name: i.name,
      label: i.label,
      description: i.description,
      ipv4_mode: i.ipv4_mode,
      dns_listen: i.dns_listen,
      dns_from_dhcp: i.dns_from_dhcp,
    })),
  })
  serverForm.mark()
}
watch(() => store.currentId, load, { immediate: true })

const fallback = computed({
  get: () => server.dns_forward_mode !== 'only',
  set: (v) => (server.dns_forward_mode = v ? 'first' : 'only'),
})
const dnssecValidation = computed({
  get: () => server.dns_dnssec_validation !== 'no',
  set: (v) => (server.dns_dnssec_validation = v ? 'auto' : 'no'),
})
const dhcpUpstream = computed(() => server.dns_upstream === 'dhcp')
const { search: ifaceSearch, filtered: shownIfaces } = useSearch(
  () => server.ifaces,
  (i) => `${withLabel(i.label, i.name)} ${i.description}`,
)

// The interfaces that are DHCP clients, which can give the upstream servers.
const dhcpIfaces = computed(() => server.ifaces.filter((i) => i.ipv4_mode === 'dhcp'))
const { search: dhcpSearch, filtered: shownDhcpIfaces } = useSearch(
  () => dhcpIfaces.value,
  (i) => `${withLabel(i.label, i.name)} ${i.description}`,
)

// Only one interface gives the upstream servers.
function setFromDhcp(ifc, on) {
  for (const i of server.ifaces) i.dns_from_dhcp = on && i === ifc
}

// Query types offered for the query log filter; others can be typed.
const queryTypes = [
  'A',
  'AAAA',
  'ANY',
  'CNAME',
  'DS',
  'DNSKEY',
  'HTTPS',
  'MX',
  'NS',
  'PTR',
  'SOA',
  'SRV',
  'SVCB',
  'TXT',
]
const queryTypeItems = computed(() => [...new Set([...queryTypes, ...server.dns_query_log_types])])
function addQueryType(item) {
  const t = item.trim().toUpperCase()
  if (t && !server.dns_query_log_types.includes(t)) {
    server.dns_query_log_types = [...server.dns_query_log_types, t]
  }
}

const noForwarders = computed(
  () => server.dns_upstream === 'forward' && !server.dns_forwarders.length,
)

async function save() {
  if (noForwarders.value) {
    toast.add({ title: 'Forwarders: enter at least one DNS server', color: 'error' })
    return
  }
  saving.value = true
  try {
    const { ifaces, ...dns } = server
    await instances.update(store.currentId, dns)
    // Clear the flag before setting it elsewhere; the server moves it anyway.
    const changed = ifaces
      .filter((i) => {
        const o = loaded.ifs.find((x) => x.id === i.id)
        return o && (o.dns_listen !== i.dns_listen || o.dns_from_dhcp !== i.dns_from_dhcp)
      })
      .sort((a, b) => Number(a.dns_from_dhcp) - Number(b.dns_from_dhcp))
    for (const i of changed) {
      await interfaces.update(i.id, { dns_listen: i.dns_listen, dns_from_dhcp: i.dns_from_dhcp })
    }
    toast.add({ title: 'DNS server saved', color: 'success' })
    await Promise.all([load(), store.load()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}

const typeLabel = (t) => zoneTypes.find((x) => x.value === t)?.label ?? t
// A forward-only zone has no records: Edit opens its form.
const forwardOnly = (z) => z.type === 'forward-only'
const zoneLink = (z) => (forwardOnly(z) ? null : `/dns/zones/${z.id}`)
const zoneColumns = [
  { key: 'name', label: 'Zone', class: 'font-mono font-medium' },
  { key: 'type', label: 'Type', format: (r) => typeLabel(r.type) },
  {
    key: 'template',
    label: 'DNS template',
    format: (r) =>
      forwardOnly(r)
        ? ''
        : (templates.value.find((t) => t.id === r.dns_template_id)?.name ?? 'built-in'),
  },
  { key: 'forwarders', label: 'Forwarders', format: (r) => (r.forwarders ?? []).join(', ') },
  { key: 'description', label: 'Description' },
]
const zoneFields = [
  // Records belong to forward zones only, so a zone keeps its type; its name can change.
  {
    key: 'type',
    label: 'Type',
    type: 'select',
    items: zoneTypes,
    disabled: (f) => !!f.id,
    hint: 'Cannot change once the zone exists.',
  },
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'home.arpa, or 192.168.1.0/24 for reverse',
  },
  {
    key: 'dns_template_id',
    label: 'DNS template',
    type: 'select',
    nullable: true,
    items: () => templates.value.map((t) => ({ label: t.name, value: t.id })),
    hint: 'SOA, NS and default TTL come from the template. —: built-in (NS localhost).',
    show: (f) => !forwardOnly(f),
  },
  {
    key: 'forwarders',
    label: 'Forwarders',
    type: 'addrs',
    required: true,
    placeholder: '172.25.130.32',
    hint: 'The DNS servers the queries for this zone are sent to: addresses or named hosts.',
    show: forwardOnly,
  },
  { key: 'description', label: 'Description' },
]
const zoneDefaults = () => ({
  type: 'forward',
  dns_template_id: templates.value[0]?.id ?? null,
  forwarders: [],
})

const tabs = [
  { label: 'DNS zones', value: 'zones', slot: 'zones', icon: 'i-lucide-globe' },
  { label: 'DNS templates', value: 'templates', slot: 'templates', icon: 'i-lucide-file-cog' },
  { label: 'DNS server', value: 'server', slot: 'server', icon: 'i-lucide-server' },
]
// The tab is in the URL (?tab=server), so links can open one.
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'zones'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'zones' ? undefined : v } }),
})
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
      <template #zones>
        <div class="space-y-4 pt-2">
          <CrudPage
            title="DNS zones"
            noun="DNS zone"
            description="Zones served by this virtual firewall's DNS server (BIND, via dnsmgr2). Names of IPAM addresses go into the matching forward zone; PTRs in reverse zones are generated. Open a zone to edit its records. A forward-only zone has no records: its queries go to its forwarders."
            :api="dnsZones"
            :params="{ instance_id: store.currentId }"
            :columns="zoneColumns"
            :fields="zoneFields"
            :defaults="zoneDefaults"
            :edit-to="zoneLink"
            new-label="New zone"
          >
            <template #cell-name="{ row }">
              <RouterLink
                v-if="zoneLink(row)"
                class="font-mono font-medium text-primary"
                :to="zoneLink(row)"
              >
                {{ row.name }}
              </RouterLink>
              <span v-else class="font-mono font-medium">{{ row.name }}</span>
            </template>
          </CrudPage>
        </div>
      </template>

      <template #templates>
        <DnsTemplates @changed="loadTemplates" />
      </template>

      <template #server>
        <div class="pt-2">
          <div class="card">
            <form @submit.prevent="save">
              <h2 class="border-b border-default pb-1 mb-2 text-xl font-semibold">DNS server</h2>

              <!-- Outside the form's fieldset, so a viewer can search too. -->
              <div class="pt-3">
                <div class="mb-2">
                  <SearchInput v-model="ifaceSearch" />
                </div>
                <fieldset :disabled="readOnly" class="min-w-0 overflow-x-auto">
                  <table class="w-full text-sm">
                    <thead>
                      <tr class="border-b border-default text-left text-xs text-muted">
                        <th class="py-1 pr-4 font-medium">Interface</th>
                        <th class="pr-4 font-medium">Description</th>
                        <th class="pr-4 font-medium">Respond to DNS queries</th>
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
                            v-model="i.dns_listen"
                            :aria-label="`Respond to DNS queries on ${i.name}`"
                          />
                        </td>
                      </tr>
                      <tr v-if="!shownIfaces.length">
                        <td colspan="3" class="py-2 text-muted">
                          {{
                            server.ifaces.length
                              ? 'No interface matches.'
                              : 'This virtual firewall has no interfaces.'
                          }}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </fieldset>
              </div>

              <h2 class="border-b border-default pb-1 mt-8 mb-2 text-xl font-semibold">
                DNS resolver
              </h2>
              <p class="mb-4 text-sm text-muted">
                Who resolves the names that are not in this virtual firewall's zones.
              </p>
              <fieldset :disabled="readOnly" class="space-y-3">
                <UFormField label="Upstream DNS" :ui="inlineField">
                  <URadioGroup v-model="server.dns_upstream" :items="upstreams" />
                </UFormField>
              </fieldset>

              <!-- Outside the form's fieldset, so a viewer can search too. -->
              <div v-if="dhcpUpstream" class="pt-3">
                <div class="mb-2">
                  <SearchInput v-model="dhcpSearch" />
                </div>
                <fieldset :disabled="readOnly" class="min-w-0 overflow-x-auto">
                  <table class="w-full text-sm">
                    <thead>
                      <tr class="border-b border-default text-left text-xs text-muted">
                        <th class="py-1 pr-4 font-medium">Interface</th>
                        <th class="pr-4 font-medium">Description</th>
                        <th class="font-medium">Use DNS from DHCP</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr
                        v-for="i in shownDhcpIfaces"
                        :key="i.id"
                        class="border-b border-default last:border-0"
                      >
                        <td class="py-1 pr-4 font-mono">{{ withLabel(i.label, i.name) }}</td>
                        <td class="py-1 pr-4">{{ i.description }}</td>
                        <td class="py-1">
                          <USwitch
                            :model-value="i.dns_from_dhcp"
                            :aria-label="`Use DNS servers from the DHCP lease on ${i.name}`"
                            @update:model-value="(v) => setFromDhcp(i, v)"
                          />
                        </td>
                      </tr>
                      <tr v-if="dhcpIfaces.length && !shownDhcpIfaces.length">
                        <td colspan="3" class="py-2 text-muted">No interface matches.</td>
                      </tr>
                    </tbody>
                  </table>
                  <p v-if="dhcpUpstream && !dhcpIfaces.length" class="mt-2 text-sm text-warning">
                    No interface gets its IPv4 address from DHCP. Make one a DHCP client under
                    Interfaces, or pick another upstream.
                  </p>
                  <p
                    v-else-if="dhcpUpstream && !server.ifaces.some((i) => i.dns_from_dhcp)"
                    class="mt-2 text-sm text-warning"
                  >
                    Choose the interface whose DHCP lease gives the DNS servers.
                  </p>
                </fieldset>
              </div>

              <fieldset :disabled="readOnly" class="mt-3 space-y-3">
                <UFormField
                  v-if="server.dns_upstream === 'forward'"
                  label="Forwarders"
                  required
                  :error="noForwarders && 'Enter at least one DNS server.'"
                  :ui="inlineField"
                >
                  <AddrInput v-model="server.dns_forwarders" multiple placeholder="9.9.9.9" />
                </UFormField>
                <UFormField
                  v-if="server.dns_upstream !== 'root'"
                  label="Fall back to the root servers"
                  help="When the upstream servers don't answer. Off: never ask anyone else."
                  :ui="inlineField"
                >
                  <USwitch v-model="fallback" />
                </UFormField>
                <UFormField
                  label="Allow recursion from"
                  help="Empty: the networks of the interfaces it Responds on."
                  :ui="inlineField"
                >
                  <AddrInput
                    v-model="server.dns_allow_recursion"
                    multiple
                    placeholder="192.168.0.0/16"
                  />
                </UFormField>
                <UFormField
                  label="DNSSEC validation"
                  help="Check the signatures of signed zones, with the built-in root key. Off: answers are not validated; turn it off only if an upstream breaks DNSSEC."
                  :ui="inlineField"
                >
                  <USwitch v-model="dnssecValidation" />
                </UFormField>
              </fieldset>

              <h2 class="border-b border-default pb-1 mt-8 mb-2 text-xl font-semibold">
                Query logging
              </h2>
              <p class="mb-4 text-sm text-muted">
                Log the queries the DNS server answers, shown under DNS queries in the log panel.
                Each filter left empty matches any query; a query is shown when it matches all of
                them.
              </p>
              <fieldset :disabled="readOnly" class="space-y-3">
                <UFormField label="Log queries" :ui="inlineField">
                  <USwitch v-model="server.dns_query_log" />
                </UFormField>
                <template v-if="server.dns_query_log">
                  <UFormField
                    label="Clients"
                    help="Only queries from these addresses or prefixes."
                    :ui="inlineField"
                  >
                    <AddrInput
                      v-model="server.dns_query_log_clients"
                      multiple
                      placeholder="192.168.1.0/24"
                    />
                  </UFormField>
                  <UFormField
                    label="Names"
                    help="Only queries for these domains and the names below them."
                    :ui="inlineField"
                  >
                    <TagsInput v-model="server.dns_query_log_names" placeholder="example.com" />
                  </UFormField>
                  <UFormField
                    label="Query types"
                    help="Only queries of these types."
                    :ui="inlineField"
                  >
                    <UInputMenu
                      v-model="server.dns_query_log_types"
                      multiple
                      create-item
                      class="w-full"
                      :items="queryTypeItems"
                      placeholder="A, AAAA"
                      @create="addQueryType"
                    />
                  </UFormField>
                </template>
              </fieldset>

              <h2 class="border-b border-default pb-1 mt-8 mb-2 text-xl font-semibold">
                DNS authoritative server
              </h2>
              <p class="text-sm text-muted">
                Will answer for the zones under the
                <RouterLink to="/dns" class="text-primary">DNS zones</RouterLink> tab.
              </p>

              <div v-if="!readOnly" class="mt-4">
                <UButton type="submit" :loading="saving">Save</UButton>
              </div>
            </form>
          </div>
        </div>
      </template>
    </UTabs>
  </NeedInstance>
</template>
