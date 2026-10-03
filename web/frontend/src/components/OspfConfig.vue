<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// OspfConfig: one OSPF version's configuration (2: OSPFv2, IPv4; 3:
// OSPFv3, IPv6): OSPF itself (one row per instance and version, made on
// the first save) and the interfaces it runs on.
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import CrudPage from '@/components/CrudPage.vue'
import EntriesEditor from '@/components/EntriesEditor.vue'
import NameSelect from '@/components/NameSelect.vue'
import { ospfConfig, ospfInterfaces } from '@/api'
import { errMsg } from '@/api/http'
import { usePageForm } from '@/composables/useFormGuard'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useRoutingObjects } from '@/composables/useRoutingObjects'
import { useAuthStore } from '@/stores/auth'
import { inlineField } from '@/utils/form'

const props = defineProps({
  version: { type: Number, required: true },
})

const toast = useToast()
const auth = useAuthStore()
const objects = useRoutingObjects()
const { store, ifaceNames, ifaceText } = useInstanceRefs()
const readOnly = computed(() => !auth.canEdit)
const v2 = computed(() => props.version === 2)
const name = computed(() => (v2.value ? 'OSPFv2' : 'OSPFv3'))
const example = computed(() => (v2.value ? '10.0.0.0/16' : '2001:db8::/48'))

// ----- OSPF itself.
const cfg = reactive({})
const cfgForm = usePageForm(cfg)
const saving = ref(false)
const defaults = () => ({
  id: 0,
  version: props.version,
  enabled: false,
  router_id: '',
  reference_bandwidth: 0,
  log_adjacency_changes: true,
  maximum_paths: 0,
  default_originate: false,
  default_always: false,
  areas: [],
  ranges: [],
  summaries: [],
  networks: [],
  redistribute: [],
})
async function load() {
  if (!store.currentId) return
  try {
    const [row] = await ospfConfig.list({ instance_id: store.currentId, version: props.version })
    for (const k of Object.keys(cfg)) delete cfg[k]
    Object.assign(cfg, defaults(), row ?? {})
    cfgForm.mark()
  } catch (err) {
    toast.add({ title: errMsg(err, `Failed to load ${name.value}`), color: 'error' })
  }
}
watch(() => store.currentId, load, { immediate: true })

async function save() {
  saving.value = true
  const body = { ...cfg, instance_id: store.currentId, version: props.version }
  for (const k of ['reference_bandwidth', 'maximum_paths']) body[k] = Number(body[k]) || 0
  try {
    const saved = cfg.id ? await ospfConfig.update(cfg.id, body) : await ospfConfig.create(body)
    Object.assign(cfg, saved)
    cfgForm.mark()
    toast.add({ title: `${name.value} saved; commit to apply it.`, color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
  } finally {
    saving.value = false
  }
}

const areaTypes = [
  { label: 'normal', value: 'normal' },
  { label: 'stub', value: 'stub' },
  { label: 'NSSA', value: 'nssa' },
]
const areaColumns = [
  { key: 'id', label: 'Area', placeholder: '0.0.0.1' },
  { key: 'type', label: 'Type', type: 'select', items: areaTypes },
  { key: 'no_summary', label: 'No summary', type: 'switch' },
]
const rangeColumns = computed(() => [
  { key: 'area', label: 'Area', placeholder: '0.0.0.1' },
  { key: 'prefix', label: 'Prefix', placeholder: example.value },
  { key: 'not_advertise', label: 'Not advertised', type: 'switch' },
  { key: 'cost', label: 'Cost', type: 'number', placeholder: 'highest inside' },
])
const summaryColumns = computed(() => [
  { key: 'prefix', label: 'Prefix', placeholder: example.value },
  { key: 'not_advertise', label: 'Not advertised', type: 'switch' },
])
const networkColumns = [
  { key: 'prefix', label: 'Prefix', placeholder: '10.0.0.0/24' },
  { key: 'area', label: 'Area', placeholder: '0.0.0.0' },
]

// Redistribution: one row per source, kept in cfg.redistribute while on.
const sources = [
  { source: 'connected', label: 'Connected', hint: 'The networks of the interfaces.' },
  {
    source: 'static',
    label: 'Static',
    hint: 'The static routes (Network > Routing > Static routes).',
  },
  { source: 'bgp', label: 'BGP', hint: "BGP's routes (Network > Routing > BGP)." },
]
const redist = (source) => cfg.redistribute?.find((r) => r.source === source)
function setRedist(source, on) {
  const list = (cfg.redistribute ?? []).filter((r) => r.source !== source)
  if (on) list.push({ source, route_map: '', metric: 0, metric_type: 2 })
  cfg.redistribute = sources.flatMap((s) => list.filter((r) => r.source === s.source))
}
const metricTypes = [
  { label: 'type 2', value: 2 },
  { label: 'type 1', value: 1 },
]

// ----- Interfaces.
const ifaceItems = computed(() => ifaceNames.value.map((n) => ({ label: ifaceText(n), value: n })))
const ifColumns = computed(() => [
  { key: 'name', label: 'Interface', format: (i) => ifaceText(i.name) },
  { key: 'area', label: 'Area', class: 'font-mono' },
  { key: 'passive', label: 'Passive' },
  { key: 'cost', label: 'Cost', format: (i) => (i.cost ? String(i.cost) : 'auto') },
  {
    key: 'network_type',
    label: 'Network type',
    format: (i) => i.network_type || 'the interface’s',
  },
  ...(v2.value
    ? [{ key: 'auth', label: 'MD5', format: (i) => (i.has_auth_key ? 'yes' : '') }]
    : []),
])
const ifFields = computed(() => [
  { key: 'name', label: 'Interface', type: 'select', items: ifaceItems.value, required: true },
  {
    key: 'area',
    label: 'Area',
    placeholder: '0.0.0.0',
    required: !v2.value,
    hint: v2.value
      ? 'Runs OSPF on all the IPv4 networks of the interface. Empty: only sets the options, for an interface a network statement covers.'
      : 'Runs OSPFv3 on the interface.',
  },
  {
    key: 'passive',
    label: 'Passive',
    type: 'switch',
    hint: "Announces the interface's networks but sends no hellos: no neighbours there.",
  },
  { key: 'cost', label: 'Cost', type: 'number', hint: '0: from the reference bandwidth.' },
  {
    key: 'hello_interval',
    label: 'Hello interval (s)',
    type: 'number',
    hint: '0: 10 s. Must match the neighbours.',
  },
  {
    key: 'dead_interval',
    label: 'Dead interval (s)',
    type: 'number',
    hint: '0: 40 s. Must match the neighbours.',
  },
  { key: 'priority', label: 'Priority', type: 'custom' },
  {
    key: 'network_type',
    label: 'Network type',
    type: 'select',
    nullable: true,
    text: true,
    items: [
      { label: 'broadcast', value: 'broadcast' },
      { label: 'point-to-point', value: 'point-to-point' },
    ],
    hint: "Empty: the interface's. Point-to-point skips the DR election (links, tunnels).",
  },
  ...(v2.value ? [{ key: 'auth_key', label: 'MD5 key', type: 'custom' }] : []),
])
const ifDefaults = computed(() => ({
  version: props.version,
  name: '',
  area: '0.0.0.0',
  passive: false,
  cost: 0,
  hello_interval: 0,
  dead_interval: 0,
  priority: null,
  network_type: '',
  auth_key_id: 0,
}))
</script>

<template>
  <div class="space-y-4">
    <div class="card">
      <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div class="text-lg font-semibold">{{ name }}</div>
          <p class="max-w-3xl text-sm text-muted">
            {{ name }} ({{ v2 ? 'IPv4' : 'IPv6' }}) runs FRR's {{ v2 ? 'ospfd' : 'ospf6d' }} in this
            virtual firewall. It is off until enabled here; changes take effect when committed. The
            firewall lets OSPF in and out on its interfaces by itself.
          </p>
        </div>
        <UButton
          v-if="!readOnly"
          label="Save"
          :loading="saving"
          :disabled="!cfgForm.dirty()"
          @click="save"
        />
      </div>
      <fieldset :disabled="readOnly" class="max-w-3xl space-y-3">
        <UFormField label="Enabled" :ui="inlineField" help="Starts the daemon; off stops it.">
          <USwitch v-model="cfg.enabled" />
        </UFormField>
        <UFormField
          label="Router id"
          :ui="inlineField"
          :help="
            v2
              ? 'An IPv4 address; empty: FRR picks one.'
              : 'An IPv4 address, also for OSPFv3; empty: FRR picks one (an IPv4 address of the firewall).'
          "
        >
          <UInput v-model="cfg.router_id" class="w-48" :ui="{ base: 'font-mono' }" />
        </UFormField>
        <UFormField
          label="Reference bandwidth"
          :ui="inlineField"
          help="Mbit/s of cost 1; an interface's cost follows from its speed. 0: 100 Mbit/s. Use the same on all routers."
        >
          <UInput v-model="cfg.reference_bandwidth" type="number" class="w-36" />
        </UFormField>
        <UFormField label="Log adjacency changes" :ui="inlineField">
          <USwitch v-model="cfg.log_adjacency_changes" />
        </UFormField>
        <UFormField
          label="Maximum paths"
          :ui="inlineField"
          help="Equal-cost paths installed; 0: FRR's default."
        >
          <UInput v-model="cfg.maximum_paths" type="number" class="w-28" />
        </UFormField>
        <UFormField
          label="Default originate"
          :ui="inlineField"
          help="Announces a default route while the routing table has one, or always."
        >
          <div class="flex items-center gap-4">
            <USwitch v-model="cfg.default_originate" />
            <USwitch v-if="cfg.default_originate" v-model="cfg.default_always" label="Always" />
          </div>
        </UFormField>

        <div class="border-b border-default pt-2 pb-1 text-sm font-semibold">Areas</div>
        <UFormField
          label="Area types"
          :ui="inlineField"
          help="An area named by an interface or network is a normal one unless listed here. A stub area gets no external routes; no summary also keeps the other areas' routes out (a default route instead)."
        >
          <EntriesEditor
            v-model="cfg.areas"
            :columns="areaColumns"
            :new-entry="() => ({ id: '', type: 'stub', no_summary: false })"
            :disabled="readOnly"
            add-label="Add area"
            empty="All areas are normal."
          />
        </UFormField>
        <UFormField
          v-if="v2"
          label="Networks"
          :ui="inlineField"
          help="Runs OSPF on the interfaces with an address in the prefix: the other way to enable it than an interface's area. FRR does not allow both."
        >
          <EntriesEditor
            v-model="cfg.networks"
            :columns="networkColumns"
            :new-entry="() => ({ prefix: '', area: '0.0.0.0' })"
            :disabled="readOnly"
            add-label="Add network"
            empty="No network statements; the interfaces below name their areas."
          />
        </UFormField>

        <div class="border-b border-default pt-2 pb-1 text-sm font-semibold">Summary addresses</div>
        <UFormField
          label="Area ranges"
          :ui="inlineField"
          help="On an area border router: the area's networks inside the prefix are announced to the other areas as the prefix alone, or not at all."
        >
          <EntriesEditor
            v-model="cfg.ranges"
            :columns="rangeColumns"
            :new-entry="() => ({ area: '', prefix: '', not_advertise: false, cost: 0 })"
            :disabled="readOnly"
            add-label="Add range"
            empty="No area ranges."
          />
        </UFormField>
        <UFormField
          label="External summaries"
          :ui="inlineField"
          help="The redistributed routes inside the prefix are announced as the prefix alone, or not at all."
        >
          <EntriesEditor
            v-model="cfg.summaries"
            :columns="summaryColumns"
            :new-entry="() => ({ prefix: '', not_advertise: false })"
            :disabled="readOnly"
            add-label="Add summary"
            empty="No external summaries."
          />
        </UFormField>

        <div class="border-b border-default pt-2 pb-1 text-sm font-semibold">Redistribute</div>
        <p class="text-sm text-muted">
          Announces these routes into OSPF as external routes. A route map filters or changes them.
          The metric (empty: 20) is their cost; type 2 keeps it as it is, type 1 adds the cost of
          the way to this router.
        </p>
        <UFormField
          v-for="s in sources"
          :key="s.source"
          :label="s.label"
          :help="s.hint"
          :ui="inlineField"
        >
          <div class="flex w-full flex-wrap items-center gap-2">
            <USwitch
              :model-value="!!redist(s.source)"
              @update:model-value="(on) => setRedist(s.source, on)"
            />
            <template v-if="redist(s.source)">
              <NameSelect
                :model-value="redist(s.source).route_map"
                class="min-w-40 flex-1"
                :items="objects.routeMapItems.value"
                :disabled="readOnly"
                placeholder="no route map"
                @update:model-value="(v) => (redist(s.source).route_map = v)"
              />
              <UInput
                :model-value="redist(s.source).metric || ''"
                type="number"
                class="w-28"
                placeholder="metric"
                :disabled="readOnly"
                @update:model-value="(v) => (redist(s.source).metric = Number(v) || 0)"
              />
              <USelect
                :model-value="redist(s.source).metric_type || 2"
                :items="metricTypes"
                class="w-28"
                :disabled="readOnly"
                @update:model-value="(v) => (redist(s.source).metric_type = v)"
              />
            </template>
          </div>
        </UFormField>
      </fieldset>
    </div>

    <CrudPage
      :title="`${name} interfaces`"
      :description="`The interfaces ${name} runs on, and their options. Link ends between virtual firewalls are interfaces too.`"
      :api="ospfInterfaces"
      :params="{ instance_id: store.currentId, version }"
      :columns="ifColumns"
      :fields="ifFields"
      :defaults="ifDefaults"
      noun="interface"
      new-label="Add interface"
      :item-name="(i) => `${name} on interface ${ifaceText(i.name)}`"
    >
      <template #field-priority="{ form }">
        <UInput
          :model-value="form.priority ?? ''"
          type="number"
          class="w-28"
          placeholder="1"
          @update:model-value="(v) => (form.priority = v === '' || v == null ? null : Number(v))"
        />
        <span class="ms-2 text-sm text-muted">In the DR election; 0 never becomes DR.</span>
      </template>
      <template #field-auth_key="{ form }">
        <div class="flex w-full flex-wrap items-center gap-2">
          <UInput
            v-model="form.new_auth_key"
            type="password"
            autocomplete="new-password"
            class="min-w-48 flex-1"
            :disabled="form.clear_auth_key"
            :placeholder="form.has_auth_key ? 'set; leave empty to keep it' : 'none'"
          />
          <span class="text-sm text-muted">key id</span>
          <UInput
            v-model.number="form.auth_key_id"
            type="number"
            class="w-20"
            placeholder="1"
            :disabled="form.clear_auth_key"
          />
          <USwitch v-if="form.has_auth_key" v-model="form.clear_auth_key" label="Remove" />
        </div>
      </template>
    </CrudPage>
  </div>
</template>
