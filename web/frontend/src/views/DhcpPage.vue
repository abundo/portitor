<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import AddrInput from '@/components/AddrInput.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { api, instances, interfaces, ipamPrefixes } from '@/api'
import { errMsg } from '@/api/http'
import { withLabel } from '@/composables/useInstanceRefs'
import { useFormGuard, usePageForm } from '@/composables/useFormGuard'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { inlineField, wideModal } from '@/utils/form'
import { suggestDhcpRange } from '@/utils/dhcp'
import { datetime } from '@/utils/time'
import { useSearch, valuesText } from '@/utils/search'

const toast = useToast()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const store = useInstanceStore()
const readOnly = computed(() => !auth.canEdit)
const leases = ref(null)
const leaseError = ref('')

onMounted(async () => {
  try {
    leases.value = await api.agentLeases()
  } catch (err) {
    leaseError.value = errMsg(err)
  }
})

const serverLeases = computed(() => leases.value?.server?.[store.current?.name] ?? [])
const clientLeases = computed(() =>
  (leases.value?.client ?? []).filter((l) => l.instance === store.current?.name),
)
const { search: leaseSearch, filtered: shownServerLeases } = useSearch(serverLeases, (l) =>
  valuesText(l.address, l.mac, l.hostname, datetime(l.expires)),
)
const { search: clientSearch, filtered: shownClientLeases } = useSearch(clientLeases, (l) =>
  valuesText(
    l.interface,
    l.family === 'ipv6' ? 'DHCPv6' : 'DHCPv4',
    l.state,
    l.address,
    l.prefixes,
    l.router,
    l.dns,
    datetime(l.expires),
  ),
)

// The DHCP settings a prefix (ipam_prefixes) holds. A prefix is served on
// the interface with an address of the same prefix, so the page lists the
// interfaces with the prefixes of their addresses.
const prefixFields = [
  'dhcp_enabled',
  'dhcp_range_start',
  'dhcp_range_end',
  'dhcp_gateway',
  'dhcp_dns_servers',
  'ra_enabled',
  'ra_slaac',
]
function prefixRow(cidr, stored, fwAddr = '') {
  return {
    id: stored?.id ?? 0,
    prefix: cidr,
    description: stored?.description ?? '',
    fw_addr: fwAddr, // the firewall's address in the prefix
    dhcp_enabled: stored?.dhcp_enabled ?? false,
    dhcp_range_start: stored?.dhcp_range_start ?? '',
    dhcp_range_end: stored?.dhcp_range_end ?? '',
    dhcp_gateway: stored?.dhcp_gateway ?? '',
    dhcp_dns_servers: stored?.dhcp_dns_servers ?? [],
    ra_enabled: stored?.ra_enabled ?? false,
    ra_slaac: stored?.ra_slaac ?? false,
  }
}
// Turning DHCP on fills in a suggested range, unless there is one.
function dhcpSwitched(p, on) {
  if (!on || p.dhcp_range_start || p.dhcp_range_end) return
  const r = suggestDhcpRange(p.prefix, p.fw_addr)
  if (r) [p.dhcp_range_start, p.dhcp_range_end] = r
}
const is6 = (p) => p.prefix.includes(':')
const is64 = (p) => p.prefix.endsWith('/64')

// The DHCP server: the instance's dhcp_* fields, and the DHCP settings of
// each interface's prefixes. orphans are prefixes with DHCP or router
// advertisements on that no interface has an address in.
const server = reactive({
  dhcp_enabled: false,
  dhcp_domain_name: '',
  dhcp_lease_time: 86400,
  ifaces: [], // { id, name, label, description, ipv4_mode, ipv6_accept_ra, prefixes: [prefixRow] }
  orphans: [],
})
const serverForm = usePageForm(server)
const saving = ref(false)
let loaded = new Map() // prefix -> its settings as loaded, to save only what changed

async function load() {
  const id = store.currentId
  if (!id) return
  const params = { instance_id: id }
  const [inst, ifs, stored, tree] = await Promise.all([
    instances.get(id),
    interfaces.list(params),
    ipamPrefixes.list(params),
    api.ipamTree(id),
  ])
  const byPrefix = new Map(stored.map((p) => [p.prefix, p]))
  // The tree's prefix nodes of an interface address carry its id; the
  // firewall's address is the interface's address node inside.
  const onIface = new Map()
  const walk = (nodes) => {
    for (const n of nodes) {
      if (n.kind !== 'prefix') continue
      if (n.interface_id) {
        const addr = n.children.find((c) => c.kind === 'address' && c.interface_id)
        const list = onIface.get(n.interface_id) ?? []
        list.push(prefixRow(n.cidr, byPrefix.get(n.cidr), addr?.cidr))
        onIface.set(n.interface_id, list)
      }
      walk(n.children)
    }
  }
  walk(tree)
  const served = new Set([...onIface.values()].flat().map((p) => p.prefix))
  Object.assign(server, {
    dhcp_enabled: inst.dhcp_enabled,
    dhcp_domain_name: inst.dhcp_domain_name ?? '',
    dhcp_lease_time: inst.dhcp_lease_time,
    ifaces: ifs.map((i) => ({
      id: i.id,
      name: i.name,
      label: i.label,
      description: i.description,
      ipv4_mode: i.ipv4_mode,
      ipv6_accept_ra: i.ipv6_accept_ra,
      prefixes: onIface.get(i.id) ?? [],
    })),
    orphans: stored
      .filter((p) => (p.dhcp_enabled || p.ra_enabled) && !served.has(p.prefix))
      .map((p) => prefixRow(p.prefix, p)),
  })
  loaded = new Map(allPrefixes().map((p) => [p.prefix, settings(p)]))
  serverForm.mark()
}
watch(() => store.currentId, load, { immediate: true })

const allPrefixes = () => [...server.ifaces.flatMap((i) => i.prefixes), ...server.orphans]
const settings = (p) => JSON.stringify(prefixFields.map((k) => p[k]))

async function save() {
  saving.value = true
  try {
    const { dhcp_enabled, dhcp_domain_name, dhcp_lease_time } = server
    await instances.update(store.currentId, { dhcp_enabled, dhcp_domain_name, dhcp_lease_time })
    for (const p of allPrefixes()) {
      if (settings(p) === loaded.get(p.prefix)) continue
      const body = Object.fromEntries(prefixFields.map((k) => [k, p[k]]))
      if (!is6(p)) body.ra_enabled = body.ra_slaac = false
      else body.dhcp_gateway = ''
      if (p.id) await ipamPrefixes.update(p.id, body)
      else await ipamPrefixes.create({ ...body, instance_id: store.currentId, prefix: p.prefix })
    }
    toast.add({ title: 'DHCP server saved', color: 'success' })
    await Promise.all([load(), store.load()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}

// ----- the interface's details: the DHCP settings of its prefixes -----
const detailOpen = ref(false)
const detail = reactive({ title: '', prefixes: [] })
let detailTarget = null // the prefix rows of the page the dialog edits
const detailGuard = useFormGuard(detail, detailOpen)
function openDetail(title, prefixes) {
  detailTarget = prefixes
  Object.assign(detail, { title, prefixes: prefixes.map((p) => JSON.parse(JSON.stringify(p))) })
  detailOpen.value = true
}
// Save copies the dialog into the page and saves the page's form.
async function saveDetail() {
  detail.prefixes.forEach((p, i) => Object.assign(detailTarget[i], p))
  detailOpen.value = false
  await save()
}

const rangeText = (p) =>
  p.dhcp_range_start ? `${p.dhcp_range_start} – ${p.dhcp_range_end}` : 'reservations only'
const gatewayText = (p) => p.dhcp_gateway || (p.fw_addr ? `firewall (${p.fw_addr})` : 'firewall')

// The DHCP server's interfaces the search finds, by what their rows show.
const { search: ifaceSearch, filtered: shownIfaces } = useSearch(
  () => server.ifaces,
  (i) =>
    valuesText(
      withLabel(i.label, i.name),
      i.description,
      i.prefixes.map((p) => [
        p.prefix,
        p.dhcp_enabled ? [rangeText(p), gatewayText(p)] : [],
        p.dhcp_dns_servers,
      ]),
    ),
)

const tabs = [
  { label: 'Leases', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'DHCP server', value: 'server', slot: 'server', icon: 'i-lucide-server' },
]
// The tab is in the URL (?tab=server), so links can open one.
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
      <template #info>
        <div class="space-y-4 pt-2">
          <UAlert
            v-if="store.current && !store.current.dhcp_enabled"
            color="warning"
            variant="subtle"
            icon="i-lucide-triangle-alert"
            title="The DHCP server is off for this instance"
            description="Turn it on, and DHCP on an interface, on the DHCP server tab."
          />
          <div class="card">
            <div class="mb-2 text-lg font-semibold">Active leases</div>
            <UAlert v-if="leaseError" color="error" variant="subtle" :title="leaseError" />
            <template v-else>
              <div class="mb-2">
                <SearchInput v-model="leaseSearch" />
              </div>
              <UTable
                :data="shownServerLeases"
                :columns="[
                  { accessorKey: 'address', header: 'Address' },
                  { accessorKey: 'mac', header: 'MAC' },
                  { accessorKey: 'hostname', header: 'Host name' },
                  { id: 'expires', header: 'Expires' },
                ]"
              >
                <template #expires-cell="{ row }">{{ datetime(row.original.expires) }}</template>
                <template #empty
                  ><div class="py-4 text-center text-muted">
                    {{ serverLeases.length ? 'No lease matches.' : 'No active leases.' }}
                  </div></template
                >
              </UTable>
            </template>
          </div>

          <div v-if="clientLeases.length" class="card">
            <div class="mb-2 text-lg font-semibold">DHCP client</div>
            <div class="mb-2">
              <SearchInput v-model="clientSearch" />
            </div>
            <UTable
              :data="shownClientLeases"
              :columns="[
                { accessorKey: 'interface', header: 'Interface' },
                { id: 'family', header: 'Client' },
                { accessorKey: 'state', header: 'State' },
                { accessorKey: 'address', header: 'Address' },
                { id: 'prefixes', header: 'Delegated prefix' },
                { accessorKey: 'router', header: 'Gateway' },
                { id: 'dns', header: 'DNS' },
                { id: 'expires', header: 'Expires' },
              ]"
            >
              <template #family-cell="{ row }">{{
                row.original.family === 'ipv6' ? 'DHCPv6' : 'DHCPv4'
              }}</template>
              <template #prefixes-cell="{ row }">{{ row.original.prefixes?.join(', ') }}</template>
              <template #dns-cell="{ row }">{{ row.original.dns?.join(', ') }}</template>
              <template #expires-cell="{ row }">{{ datetime(row.original.expires) }}</template>
              <template #empty
                ><div class="py-4 text-center text-muted">No lease matches.</div></template
              >
            </UTable>
          </div>
        </div>
      </template>

      <template #server>
        <div class="pt-2">
          <div class="card">
            <div class="mb-1 text-lg font-semibold">DHCP server</div>
            <p class="mb-4 text-sm text-muted">
              Kea, for the clients on this instance's interfaces. DHCP is served per prefix of an
              interface address; several on one interface form a shared network, and clients get
              addresses from all of them. Fixed leases are addresses with a MAC and a DNS name under
              <RouterLink to="/objects" class="text-primary">Hosts & prefixes</RouterLink>.
            </p>
            <form @submit.prevent="save">
              <fieldset :disabled="readOnly" class="space-y-3">
                <UFormField label="DHCP server (Kea)" :ui="inlineField">
                  <USwitch v-model="server.dhcp_enabled" />
                </UFormField>
                <template v-if="server.dhcp_enabled">
                  <UFormField label="DHCP domain name" :ui="inlineField">
                    <UInput
                      v-model="server.dhcp_domain_name"
                      placeholder="home.arpa"
                      class="w-full sm:w-96"
                    />
                  </UFormField>
                  <UFormField label="Lease time (seconds)" :ui="inlineField">
                    <UInput
                      v-model.number="server.dhcp_lease_time"
                      type="number"
                      min="300"
                      class="w-full sm:w-48"
                    />
                  </UFormField>
                </template>
                <p v-else class="text-sm text-muted">
                  With the DHCP server off, the interfaces' DHCP settings are kept but not served;
                  IPv6 router advertisements are still sent.
                </p>
              </fieldset>

              <div class="mt-4 mb-2">
                <SearchInput v-model="ifaceSearch" />
              </div>
              <div class="overflow-x-auto">
                <table class="w-full text-sm">
                  <thead>
                    <tr class="border-b border-default text-left text-xs text-muted">
                      <th class="w-px py-1.5 pr-2"></th>
                      <th class="pr-4 font-medium">Interface</th>
                      <th class="pr-4 font-medium">Description</th>
                      <th class="pr-4 font-medium">Prefix</th>
                      <th class="pr-4 font-medium">DHCP server</th>
                      <th class="pr-4 font-medium">Range</th>
                      <th class="pr-4 font-medium">Gateway</th>
                      <th class="font-medium">DNS servers</th>
                    </tr>
                  </thead>
                  <tbody>
                    <template v-for="i in shownIfaces" :key="i.id">
                      <tr
                        v-for="(p, idx) in i.prefixes.length ? i.prefixes : [null]"
                        :key="p?.prefix ?? 'none'"
                        class="border-b border-default last:border-0"
                      >
                        <template v-if="idx === 0">
                          <td :rowspan="i.prefixes.length || 1" class="py-1 pr-2 align-top">
                            <UButton
                              v-if="i.prefixes.length"
                              size="xs"
                              color="neutral"
                              variant="ghost"
                              :icon="readOnly ? 'i-lucide-eye' : 'i-lucide-pencil'"
                              :aria-label="readOnly ? 'View' : 'Edit'"
                              :title="readOnly ? 'View' : 'Edit'"
                              type="button"
                              @click="openDetail(withLabel(i.label, i.name), i.prefixes)"
                            />
                          </td>
                          <td :rowspan="i.prefixes.length || 1" class="py-1.5 pr-4 align-top">
                            <div class="font-mono">{{ withLabel(i.label, i.name) }}</div>
                            <div class="mt-0.5 flex flex-wrap gap-1">
                              <UBadge
                                v-if="i.ipv4_mode === 'dhcp'"
                                color="neutral"
                                variant="subtle"
                                size="sm"
                                label="DHCP Client"
                                title="Gets its IPv4 address from a DHCP server"
                              />
                              <UBadge
                                v-if="i.ipv6_accept_ra"
                                color="neutral"
                                variant="subtle"
                                size="sm"
                                label="SLAAC-C"
                                title="Takes an IPv6 address from router advertisements (SLAAC client)"
                              />
                              <UBadge
                                v-if="i.prefixes.some((p) => p.ra_enabled)"
                                color="info"
                                variant="subtle"
                                size="sm"
                                label="RA"
                                title="Sends IPv6 router advertisements"
                              />
                            </div>
                          </td>
                          <td :rowspan="i.prefixes.length || 1" class="py-1.5 pr-4 align-top">
                            {{ i.description }}
                          </td>
                        </template>
                        <td v-if="!p" colspan="5" class="py-1.5 text-muted">
                          {{
                            i.ipv4_mode === 'dhcp'
                              ? 'DHCP client; no static address to serve DHCP on.'
                              : 'No address; give it one under Interfaces to serve DHCP.'
                          }}
                        </td>
                        <template v-else>
                          <td class="py-1.5 pr-4 font-mono">{{ p.prefix }}</td>
                          <td class="py-1.5 pr-4">
                            <div class="flex items-center gap-1.5">
                              <USwitch
                                v-model="p.dhcp_enabled"
                                :disabled="readOnly || (is6(p) && !p.ra_enabled && !p.dhcp_enabled)"
                                @update:model-value="(on) => dhcpSwitched(p, on)"
                                :title="
                                  is6(p) && !p.ra_enabled
                                    ? 'DHCPv6 needs router advertisements: open the interface'
                                    : ''
                                "
                                :aria-label="`DHCP server on ${p.prefix}`"
                              />
                              <UBadge
                                v-if="p.ra_slaac"
                                color="info"
                                variant="subtle"
                                size="sm"
                                label="SLAAC"
                                title="Clients pick their own address from this prefix"
                              />
                            </div>
                          </td>
                          <template v-if="p.dhcp_enabled">
                            <td class="py-1.5 pr-4 font-mono text-xs">{{ rangeText(p) }}</td>
                            <td class="py-1.5 pr-4 font-mono text-xs">
                              {{ is6(p) ? 'from RA' : gatewayText(p) }}
                            </td>
                          </template>
                          <td v-else colspan="2" />
                          <td class="py-1.5 font-mono text-xs">
                            <template v-if="p.dhcp_enabled || p.ra_enabled">{{
                              p.dhcp_dns_servers?.length
                                ? p.dhcp_dns_servers.join(', ')
                                : 'firewall, when it answers DNS here'
                            }}</template>
                          </td>
                        </template>
                      </tr>
                    </template>
                    <tr v-if="!shownIfaces.length">
                      <td colspan="8" class="py-2 text-muted">
                        {{
                          server.ifaces.length
                            ? 'No interface matches.'
                            : 'This instance has no interfaces.'
                        }}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div v-if="server.orphans.length" class="pt-2">
                <UAlert
                  color="warning"
                  variant="subtle"
                  icon="i-lucide-triangle-alert"
                  title="Not served: no interface has an address in these prefixes"
                >
                  <template #description>
                    <div class="mt-1 flex flex-wrap gap-2">
                      <UButton
                        v-for="p in server.orphans"
                        :key="p.prefix"
                        size="xs"
                        color="neutral"
                        variant="outline"
                        class="font-mono"
                        :icon="readOnly ? 'i-lucide-eye' : 'i-lucide-pencil'"
                        :label="p.prefix"
                        type="button"
                        @click="openDetail(p.prefix, [p])"
                      />
                    </div>
                  </template>
                </UAlert>
              </div>
              <div v-if="!readOnly" class="mt-4">
                <UButton type="submit" :loading="saving">Save</UButton>
              </div>
            </form>
          </div>
        </div>
      </template>
    </UTabs>

    <UModal
      :open="detailOpen"
      :title="`DHCP on ${detail.title}`"
      :ui="wideModal"
      :dismissible="false"
      @update:open="detailGuard.onUpdateOpen"
    >
      <template #body>
        <form id="dhcp-detail-form" @submit.prevent="saveDetail">
          <fieldset :disabled="readOnly" class="space-y-6">
            <div v-for="p in detail.prefixes" :key="p.prefix" class="space-y-3">
              <div class="border-b border-default pb-1">
                <span class="font-mono font-semibold">{{ p.prefix }}</span>
                <span v-if="p.description" class="ms-2 text-sm text-muted">{{
                  p.description
                }}</span>
              </div>
              <template v-if="is6(p)">
                <UFormField
                  :ui="inlineField"
                  label="Send router advertisements"
                  help="Announce this prefix and the firewall as default router."
                >
                  <USwitch v-model="p.ra_enabled" />
                </UFormField>
                <UFormField
                  v-if="p.ra_enabled"
                  :ui="inlineField"
                  label="SLAAC: clients pick their own address"
                  :help="is64(p) ? '' : 'Needs a /64 prefix.'"
                >
                  <USwitch v-model="p.ra_slaac" :disabled="!is64(p)" />
                </UFormField>
              </template>
              <UFormField
                :ui="inlineField"
                :label="is6(p) ? 'DHCPv6 server' : 'DHCP server'"
                :help="
                  is6(p)
                    ? 'Needs router advertisements (above) and the instance\'s DHCP server.'
                    : 'Needs the instance\'s DHCP server.'
                "
              >
                <USwitch
                  v-model="p.dhcp_enabled"
                  :disabled="is6(p) && !p.ra_enabled && !p.dhcp_enabled"
                  @update:model-value="(on) => dhcpSwitched(p, on)"
                />
              </UFormField>
              <template v-if="p.dhcp_enabled">
                <UFormField
                  :ui="inlineField"
                  label="Range"
                  help="Empty: no dynamic addresses, only the fixed leases."
                >
                  <div class="flex items-center gap-2">
                    <UInput
                      v-model="p.dhcp_range_start"
                      class="min-w-0 flex-1 font-mono"
                      :placeholder="is6(p) ? 'fd00:1::100' : '192.168.1.100'"
                      aria-label="Range start"
                    />
                    <span class="text-muted">-</span>
                    <UInput
                      v-model="p.dhcp_range_end"
                      class="min-w-0 flex-1 font-mono"
                      :placeholder="is6(p) ? 'fd00:1::1ff' : '192.168.1.199'"
                      aria-label="Range end"
                    />
                  </div>
                </UFormField>
                <UFormField
                  v-if="!is6(p)"
                  :ui="inlineField"
                  label="Gateway"
                  :help="`Empty: the firewall's address in the prefix${p.fw_addr ? ` (${p.fw_addr})` : ''}.`"
                  ><UInput v-model="p.dhcp_gateway" class="w-full font-mono"
                /></UFormField>
              </template>
              <UFormField
                v-if="p.dhcp_enabled || (is6(p) && p.ra_enabled)"
                :ui="inlineField"
                label="DNS servers"
                help="Addresses or hosts; only those of the prefix's IP version are used. Empty: the firewall, when its DNS server answers on this interface."
              >
                <AddrInput v-model="p.dhcp_dns_servers" multiple />
              </UFormField>
            </div>
          </fieldset>
        </form>
      </template>
      <template #footer>
        <div class="flex w-full gap-2">
          <UButton class="ms-auto" color="neutral" variant="ghost" @click="detailGuard.close">{{
            readOnly ? 'Close' : 'Cancel'
          }}</UButton>
          <UButton v-if="!readOnly" type="submit" form="dhcp-detail-form" :loading="saving"
            >Save</UButton
          >
        </div>
      </template>
    </UModal>
  </NeedInstance>
</template>
