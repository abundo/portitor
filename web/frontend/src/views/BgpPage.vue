<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- BGP (FRR): the neighbours' sessions and the BGP table as FRR has them
     (BGP info), and the configuration: BGP itself, peer groups and
     neighbours (Configuration). -->
<script setup>
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import BgpPeerTable from '@/components/BgpPeerTable.vue'
import EntriesEditor from '@/components/EntriesEditor.vue'
import NameSelect from '@/components/NameSelect.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { api, bgpConfig, bgpNeighbors, bgpPeerGroups } from '@/api'
import { errMsg } from '@/api/http'
import { usePageForm } from '@/composables/useFormGuard'
import { useRoutingObjects } from '@/composables/useRoutingObjects'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { inlineField } from '@/utils/form'
import { useSearch, valuesText } from '@/utils/search'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const auth = useAuthStore()
const store = useInstanceStore()
const objects = useRoutingObjects()
const readOnly = computed(() => !auth.canEdit)

const tabs = [
  { label: 'BGP info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'Configuration', value: 'config', slot: 'config', icon: 'i-lucide-settings' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})

// ----- BGP info: loaded, and refreshed every 10 s, while its tab is open.
const status = ref(null)
const statusError = ref('')
const loading = ref(false)
async function loadStatus() {
  loading.value = true
  try {
    status.value = await api.agentBgp()
    statusError.value = ''
  } catch (err) {
    statusError.value = errMsg(err)
  } finally {
    loading.value = false
  }
}
let timer = null
watch(
  tab,
  (t) => {
    clearInterval(timer)
    timer = null
    if (t === 'info') {
      loadStatus()
      timer = setInterval(loadStatus, 10000)
    }
  },
  { immediate: true },
)
onBeforeUnmount(() => clearInterval(timer))

const mine = computed(() =>
  status.value?.instances?.find((i) => i.instance === store.current?.name),
)
const peers = computed(() => mine.value?.peers ?? [])
const bgpRoutes = computed(() => mine.value?.routes ?? [])
const prefixes = (p, fam) => {
  const f = p.families?.[fam]
  return f ? `${f.prefixes_received} / ${f.prefixes_sent}` : ''
}
const peerSearch = useSearch(peers, (p) =>
  valuesText(p.address, p.description, p.hostname, p.remote_as, p.state, p.uptime, p.last_reset),
)
const routeSearch = useSearch(bgpRoutes, (r) =>
  valuesText(r.prefix, r.next_hop, r.path, r.origin, r.best && 'best'),
)
const stateColor = (s) =>
  s === 'Established' ? 'success' : s.startsWith('Idle') ? 'neutral' : 'warning'
const peerColumns = [
  { accessorKey: 'address', header: 'Neighbour' },
  { accessorKey: 'remote_as', header: 'Remote AS' },
  { accessorKey: 'state', header: 'State' },
  { accessorKey: 'uptime', header: 'Up' },
  { id: 'v4', header: 'IPv4 rcvd / sent' },
  { id: 'v6', header: 'IPv6 rcvd / sent' },
  { id: 'msgs', header: 'Messages rcvd / sent' },
  { accessorKey: 'last_reset', header: 'Last reset' },
]
const routeColumns = [
  { accessorKey: 'prefix', header: 'Prefix' },
  { accessorKey: 'next_hop', header: 'Next hop' },
  { id: 'best', header: 'Best' },
  { accessorKey: 'metric', header: 'MED' },
  { accessorKey: 'local_pref', header: 'Local pref' },
  { accessorKey: 'weight', header: 'Weight' },
  { accessorKey: 'path', header: 'AS path' },
  { accessorKey: 'origin', header: 'Origin' },
]

// ----- Configuration: BGP itself (one row per instance, made on the first
// save).
const cfg = reactive({})
const cfgForm = usePageForm(cfg)
const savingCfg = ref(false)
const defaults = () => ({
  id: 0,
  enabled: false,
  asn: 0,
  router_id: '',
  keepalive: 0,
  hold: 0,
  ebgp_requires_policy: false,
  log_neighbor_changes: true,
  graceful_restart: false,
  multipath_relax: false,
  maximum_paths: 0,
  networks: [],
  aggregates: [],
  redist_connected_v4: false,
  redist_connected_v4_map: '',
  redist_static_v4: false,
  redist_static_v4_map: '',
  redist_connected_v6: false,
  redist_connected_v6_map: '',
  redist_static_v6: false,
  redist_static_v6_map: '',
  redist_ospf_v4: false,
  redist_ospf_v4_map: '',
  redist_ospf_v6: false,
  redist_ospf_v6_map: '',
})
async function loadCfg() {
  if (!store.currentId) return
  try {
    const [row] = await bgpConfig.list({ instance_id: store.currentId })
    for (const k of Object.keys(cfg)) delete cfg[k]
    Object.assign(cfg, defaults(), row ?? {})
    cfgForm.mark()
  } catch (err) {
    toast.add({ title: errMsg(err, 'Failed to load BGP'), color: 'error' })
  }
}
watch(() => store.currentId, loadCfg, { immediate: true })

async function saveCfg() {
  savingCfg.value = true
  const body = { ...cfg, instance_id: store.currentId }
  for (const k of ['asn', 'keepalive', 'hold', 'maximum_paths']) body[k] = Number(body[k]) || 0
  try {
    const saved = cfg.id ? await bgpConfig.update(cfg.id, body) : await bgpConfig.create(body)
    Object.assign(cfg, saved)
    cfgForm.mark()
    toast.add({ title: 'BGP saved; commit to apply it.', color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
  } finally {
    savingCfg.value = false
  }
}

const networkColumns = computed(() => [
  { key: 'prefix', label: 'Prefix', placeholder: '192.0.2.0/24' },
  {
    key: 'route_map',
    label: 'Route map',
    type: 'select',
    items: [{ label: '—', value: '' }, ...objects.routeMapItems.value],
  },
])
const aggregateColumns = [
  { key: 'prefix', label: 'Prefix', placeholder: '192.0.2.0/22' },
  { key: 'summary_only', label: 'Summary only', type: 'switch' },
  { key: 'as_set', label: 'AS set', type: 'switch' },
]
const redistributions = [
  { key: 'redist_connected_v4', label: 'IPv4 connected' },
  { key: 'redist_static_v4', label: 'IPv4 static' },
  { key: 'redist_ospf_v4', label: 'IPv4 OSPF' },
  { key: 'redist_connected_v6', label: 'IPv6 connected' },
  { key: 'redist_static_v6', label: 'IPv6 static' },
  { key: 'redist_ospf_v6', label: 'IPv6 OSPF' },
]

// ----- Peer groups and neighbours.
const groups = ref([])
async function loadGroups() {
  if (store.currentId) groups.value = await bgpPeerGroups.list({ instance_id: store.currentId })
}
watch(() => store.currentId, loadGroups, { immediate: true })
const neighborPage = ref(null)
function groupsChanged() {
  loadGroups()
  neighborPage.value?.reload() // a renamed group is renamed in its neighbours
}
const groupOf = (n) => groups.value.find((g) => g.name === n.peer_group)
const families = (p) =>
  [p.v4_activate && 'IPv4', p.v6_activate && 'IPv6'].filter(Boolean).join(', ')

// peerFields are the fields of a neighbour and a peer group alike.
function peerFields() {
  const fam = (f, label, list) => [
    { key: `${f}_heading`, label, type: 'heading' },
    { key: `${f}_activate`, label: 'Activate', type: 'switch' },
    ...[
      { key: `${f}_filter_in`, label: 'Filter in', type: 'custom' },
      { key: `${f}_filter_out`, label: 'Filter out', type: 'custom' },
      { key: `${f}_next_hop_self`, label: 'Next hop self', type: 'switch' },
      {
        key: `${f}_remove_private_as`,
        label: 'Remove private AS',
        type: 'switch',
        hint: 'Leaves private AS numbers (64512-65534, ...) out of the AS path sent.',
      },
      {
        key: `${f}_soft_reconfiguration`,
        label: 'Soft reconfiguration',
        type: 'switch',
        hint: 'Keeps the routes received before the filter, so a changed filter applies without resetting the session.',
      },
      {
        key: `${f}_default_originate`,
        label: 'Default originate',
        type: 'switch',
        hint: `Sends a default route (${list}) to the neighbour.`,
      },
      { key: `${f}_route_reflector_client`, label: 'Route reflector client', type: 'switch' },
      {
        key: `${f}_allowas_in`,
        label: 'Allow own AS in',
        type: 'number',
        hint: 'Accepts routes with the local AS in their path this many times (0: off).',
      },
      {
        key: `${f}_maximum_prefix`,
        label: 'Maximum prefixes',
        type: 'number',
        hint: 'Shuts the session down when the neighbour sends more (0: no limit).',
      },
    ].map((x) => ({ ...x, show: (form) => form[`${f}_activate`] })),
  ]
  return [
    { key: 'session_heading', label: 'Session', type: 'heading' },
    {
      key: 'remote_as',
      label: 'Remote AS',
      placeholder: '65001, internal or external',
      hint: 'internal: the local AS (iBGP); external: any other AS.',
    },
    { key: 'description', label: 'Description' },
    { key: 'password', label: 'Password', type: 'custom' },
    { key: 'ebgp_multihop', label: 'eBGP multihop', type: 'custom' },
    {
      key: 'update_source',
      label: 'Update source',
      placeholder: 'an interface or address',
      hint: 'The source of the session, for a neighbour that is not directly connected (loopback peering).',
    },
    {
      key: 'passive',
      label: 'Passive',
      type: 'switch',
      hint: 'Waits for the neighbour to connect.',
    },
    { key: 'shutdown', label: 'Shut down', type: 'switch', hint: 'Keeps the session down.' },
    { key: 'keepalive', label: 'Keepalive (s)', type: 'number', hint: '0: the BGP default.' },
    { key: 'hold', label: 'Hold time (s)', type: 'number', hint: '0: three times the keepalive.' },
    ...fam('v4', 'IPv4 unicast', '0.0.0.0/0'),
    ...fam('v6', 'IPv6 unicast', '::/0'),
  ]
}
const peerDefaults = {
  remote_as: '',
  description: '',
  ebgp_multihop: 0,
  update_source: '',
  passive: false,
  shutdown: false,
  keepalive: 0,
  hold: 0,
  v4_activate: true,
  v6_activate: false,
}

const groupColumns = [
  { key: 'name', label: 'Name', class: 'font-mono' },
  { key: 'remote_as', label: 'Remote AS' },
  { key: 'families', label: 'Address families', format: families },
  {
    key: 'members',
    label: 'Neighbours',
    format: (g) => String(neighborRows.value.filter((n) => n.peer_group === g.name).length),
  },
  { key: 'description', label: 'Description' },
]
const groupFields = [{ key: 'name', label: 'Name', required: true }, ...peerFields()]

const neighborRows = ref([])
async function loadNeighborRows() {
  if (store.currentId)
    neighborRows.value = await bgpNeighbors.list({ instance_id: store.currentId })
}
watch(() => store.currentId, loadNeighborRows, { immediate: true })
const neighborColumns = [
  { key: 'address', label: 'Address', class: 'font-mono' },
  { key: 'description', label: 'Description' },
  {
    key: 'remote_as',
    label: 'Remote AS',
    format: (n) => n.remote_as || (groupOf(n)?.remote_as ? `${groupOf(n).remote_as} (group)` : ''),
  },
  { key: 'peer_group', label: 'Peer group' },
  {
    key: 'families',
    label: 'Address families',
    format: (n) => families(n) || (n.peer_group ? families(groupOf(n) ?? {}) : ''),
  },
  { key: 'enabled', label: 'Enabled' },
]
const neighborFields = computed(() => [
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'address', label: 'Address', required: true, placeholder: '192.0.2.1 or 2001:db8::1' },
  {
    key: 'peer_group',
    label: 'Peer group',
    type: 'select',
    nullable: true,
    text: true,
    items: groups.value.map((g) => ({ label: g.name, value: g.name, description: g.description })),
    hint: "The neighbour takes the group's settings; what is set here adds to them.",
  },
  ...peerFields(),
])
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs">
      <template #info>
        <div class="card">
          <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <div class="text-lg font-semibold">BGP info</div>
              <p class="max-w-3xl text-sm text-muted">
                The BGP sessions and the BGP table of this virtual firewall, as FRR has them.
              </p>
            </div>
            <UButton
              icon="i-lucide-refresh-cw"
              color="neutral"
              variant="outline"
              label="Refresh"
              :loading="loading"
              @click="loadStatus"
            />
          </div>
          <UAlert
            v-if="statusError"
            class="mb-2"
            color="error"
            variant="subtle"
            :title="statusError"
          />
          <UAlert
            v-else-if="status && !mine"
            class="mb-2"
            color="neutral"
            variant="subtle"
            title="BGP is not running in this virtual firewall."
            description="Turn it on under Configuration, then commit."
          />
          <template v-if="mine">
            <UAlert
              v-if="mine.error"
              class="mb-2"
              color="warning"
              variant="subtle"
              :title="mine.error"
            />
            <dl class="mb-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
              <dt class="text-muted">Local AS</dt>
              <dd class="font-mono">{{ mine.asn || '' }}</dd>
              <dt class="text-muted">Router id</dt>
              <dd class="font-mono">{{ mine.router_id }}</dd>
            </dl>
            <div class="mb-2 font-semibold">Neighbours</div>
            <SearchInput v-model="peerSearch.search.value" class="mb-2" />
            <UTable
              :data="peerSearch.filtered.value"
              :columns="peerColumns"
              :loading="loading && !status"
            >
              <template #address-cell="{ row }">
                <span class="font-mono text-xs">{{ row.original.address }}</span>
                <span v-if="row.original.description" class="ms-1 text-muted">
                  {{ row.original.description }}
                </span>
              </template>
              <template #state-cell="{ row }">
                <UBadge
                  :color="stateColor(row.original.state)"
                  variant="subtle"
                  :label="row.original.state"
                />
              </template>
              <template #v4-cell="{ row }">{{ prefixes(row.original, 'ipv4') }}</template>
              <template #v6-cell="{ row }">{{ prefixes(row.original, 'ipv6') }}</template>
              <template #msgs-cell="{ row }">
                {{ row.original.msg_rcvd }} / {{ row.original.msg_sent }}
              </template>
              <template #empty>
                <div class="py-4 text-center text-muted">No neighbours.</div>
              </template>
            </UTable>

            <div class="mt-6 mb-2 font-semibold">BGP table</div>
            <UAlert
              v-if="mine.routes_truncated"
              class="mb-2"
              color="neutral"
              variant="subtle"
              title="The BGP table is too large to show here (over 2000 routes in an address family); that family is left out. The console's vtysh shows it all."
            />
            <SearchInput v-model="routeSearch.search.value" class="mb-2" />
            <UTable :data="routeSearch.filtered.value" :columns="routeColumns">
              <template #prefix-cell="{ row }">
                <span class="font-mono text-xs">{{ row.original.prefix }}</span>
              </template>
              <template #next_hop-cell="{ row }">
                <span class="font-mono text-xs">{{ row.original.next_hop }}</span>
              </template>
              <template #best-cell="{ row }">
                <UIcon v-if="row.original.best" name="i-lucide-check" class="text-success" />
                <span v-else-if="!row.original.valid" class="text-xs text-muted">invalid</span>
              </template>
              <template #path-cell="{ row }">
                <span class="font-mono text-xs">{{ row.original.path }}</span>
              </template>
              <template #empty>
                <div class="py-4 text-center text-muted">No routes.</div>
              </template>
            </UTable>
          </template>
        </div>
      </template>

      <template #config>
        <div class="space-y-4">
          <div class="card">
            <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <div class="text-lg font-semibold">BGP</div>
                <p class="max-w-3xl text-sm text-muted">
                  BGP runs FRR (zebra and bgpd) in this virtual firewall. It is off until enabled
                  here; changes take effect when deployed.
                </p>
              </div>
              <UButton
                v-if="!readOnly"
                label="Save"
                :loading="savingCfg"
                :disabled="!cfgForm.dirty()"
                @click="saveCfg"
              />
            </div>
            <fieldset :disabled="readOnly" class="max-w-3xl space-y-3">
              <UFormField label="Enabled" :ui="inlineField" help="Starts FRR; off stops it.">
                <USwitch v-model="cfg.enabled" />
              </UFormField>
              <UFormField label="Local AS" required :ui="inlineField">
                <UInput v-model="cfg.asn" type="number" class="w-48" placeholder="65000" />
              </UFormField>
              <UFormField
                label="Router id"
                :ui="inlineField"
                help="An IPv4 address; empty: FRR picks one."
              >
                <UInput v-model="cfg.router_id" class="w-48" :ui="{ base: 'font-mono' }" />
              </UFormField>
              <UFormField
                label="Keepalive / hold (s)"
                :ui="inlineField"
                help="0: the BGP defaults (60 / 180)."
              >
                <div class="flex gap-2">
                  <UInput v-model="cfg.keepalive" type="number" class="w-28" />
                  <UInput v-model="cfg.hold" type="number" class="w-28" />
                </div>
              </UFormField>
              <UFormField label="Log neighbour changes" :ui="inlineField">
                <USwitch v-model="cfg.log_neighbor_changes" />
              </UFormField>
              <UFormField
                label="eBGP requires policy"
                :ui="inlineField"
                help="RFC 8212: an eBGP neighbour without a route map in and out exchanges no routes."
              >
                <USwitch v-model="cfg.ebgp_requires_policy" />
              </UFormField>
              <UFormField label="Graceful restart" :ui="inlineField">
                <USwitch v-model="cfg.graceful_restart" />
              </UFormField>
              <UFormField
                label="Multipath relax"
                :ui="inlineField"
                help="Lets paths through different neighbouring ASes share the load."
              >
                <USwitch v-model="cfg.multipath_relax" />
              </UFormField>
              <UFormField
                label="Maximum paths"
                :ui="inlineField"
                help="ECMP paths installed; 0: FRR's default."
              >
                <UInput v-model="cfg.maximum_paths" type="number" class="w-28" />
              </UFormField>

              <div class="border-b border-default pt-2 pb-1 text-sm font-semibold">Networks</div>
              <UFormField
                label="Networks"
                :ui="inlineField"
                help="Announced when the routing table has the prefix; IPv4 and IPv6."
              >
                <EntriesEditor
                  v-model="cfg.networks"
                  :columns="networkColumns"
                  :new-entry="() => ({ prefix: '', route_map: '' })"
                  :disabled="readOnly"
                  add-label="Add network"
                  empty="No networks."
                />
              </UFormField>
              <UFormField
                label="Aggregate addresses"
                :ui="inlineField"
                help="Announced while a more specific route is in the BGP table. Summary only leaves the more specific ones out."
              >
                <EntriesEditor
                  v-model="cfg.aggregates"
                  :columns="aggregateColumns"
                  :new-entry="() => ({ prefix: '', summary_only: false, as_set: false })"
                  :disabled="readOnly"
                  add-label="Add aggregate"
                  empty="No aggregate addresses."
                />
              </UFormField>

              <div class="border-b border-default pt-2 pb-1 text-sm font-semibold">
                Redistribute
              </div>
              <p class="text-sm text-muted">
                Connected: the networks of the interfaces. Static: the static routes (Network &gt;
                Routing &gt; Static routes). OSPF: OSPFv2's routes into IPv4, OSPFv3's into IPv6
                (Network &gt; Routing &gt; OSPF). A route map filters or changes what is announced.
              </p>
              <UFormField
                v-for="r in redistributions"
                :key="r.key"
                :label="r.label"
                :ui="inlineField"
              >
                <div class="flex w-full items-center gap-2">
                  <USwitch v-model="cfg[r.key]" />
                  <NameSelect
                    v-if="cfg[r.key]"
                    v-model="cfg[`${r.key}_map`]"
                    :items="objects.routeMapItems.value"
                    :disabled="readOnly"
                    placeholder="no route map"
                  />
                </div>
              </UFormField>
            </fieldset>
          </div>

          <BgpPeerTable
            title="Peer groups"
            description="Settings shared by the neighbours in a group."
            :api="bgpPeerGroups"
            :params="{ instance_id: store.currentId }"
            :columns="groupColumns"
            :fields="groupFields"
            :defaults="peerDefaults"
            new-label="New peer group"
            :disabled="readOnly"
            :prefix-list-items="objects.prefixListItems"
            :route-map-items="objects.routeMapItems.value"
            @changed="groupsChanged"
          />

          <BgpPeerTable
            ref="neighborPage"
            title="Neighbours"
            description="The BGP neighbours (peers) of this virtual firewall. The firewall opens TCP port 179 to and from them by itself."
            :api="bgpNeighbors"
            :params="{ instance_id: store.currentId }"
            :columns="neighborColumns"
            :fields="neighborFields"
            :defaults="{ ...peerDefaults, enabled: true, peer_group: '' }"
            noun="neighbour"
            new-label="New neighbour"
            :item-name="
              (n) => `neighbour ${n.address}${n.description ? ` (${n.description})` : ''}`
            "
            :disabled="readOnly"
            :prefix-list-items="objects.prefixListItems"
            :route-map-items="objects.routeMapItems.value"
            @changed="loadNeighborRows"
          />
        </div>
      </template>
    </UTabs>
  </NeedInstance>
</template>
