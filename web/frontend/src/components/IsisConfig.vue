<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// IsisConfig: IS-IS's configuration of the chosen VRF (useVrfChoice; the
// page keys it by the VRF): IS-IS itself (one row per instance and VRF,
// made on the first save) and the interfaces it runs on, those in the VRF.
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import CrudPage from '@/components/CrudPage.vue'
import EntriesEditor from '@/components/EntriesEditor.vue'
import FormHeader from '@/components/FormHeader.vue'
import { isisConfig, isisInterfaces } from '@/api'
import { errMsg } from '@/api/http'
import { usePageForm } from '@/composables/useFormGuard'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useRoutingObjects } from '@/composables/useRoutingObjects'
import { useVrfChoice } from '@/composables/useVrfChoice'
import { useAuthStore } from '@/stores/auth'
import { inlineField } from '@/utils/form'

const toast = useToast()
const auth = useAuthStore()
const objects = useRoutingObjects()
const { store, ifaceList, ifaceNames, ifaceText } = useInstanceRefs()
const { vrfName, vrfId, ofVrf } = useVrfChoice()
// inVrf reports whether an interface (or link end, in none) is in the VRF.
const inVrf = (name) => (ifaceList.value.find((i) => i.name === name)?.vrf || '') === vrfName.value
const readOnly = computed(() => !auth.canEdit)

// ----- IS-IS itself.
const cfg = reactive({})
const cfgForm = usePageForm(cfg)
const saving = ref(false)
const defaults = () => ({
  id: 0,
  enabled: false,
  net: '',
  peer_net: '',
  net_interface: '',
  net_area: '49.0001',
  level: '',
  metric_style: '',
  log_adjacency_changes: true,
  ipv6_topology: false,
  overload: false,
  area_password_type: 'md5',
  domain_password_type: 'md5',
  has_area_password: false,
  has_domain_password: false,
  new_area_password: '',
  new_domain_password: '',
  clear_area_password: false,
  clear_domain_password: false,
  default_originate: [],
  redistribute: [],
})
async function load() {
  if (!store.currentId) return
  try {
    const rows = await isisConfig.list({ instance_id: store.currentId })
    const row = rows.find(ofVrf)
    for (const k of Object.keys(cfg)) delete cfg[k]
    Object.assign(cfg, defaults(), row ?? {})
    cfgForm.mark()
  } catch (err) {
    toast.add({ title: errMsg(err, 'Failed to load IS-IS'), color: 'error' })
  }
}
watch(() => store.currentId, load, { immediate: true })

async function save() {
  saving.value = true
  const body = { ...cfg, instance_id: store.currentId, vrf_id: vrfId.value }
  try {
    const saved = cfg.id ? await isisConfig.update(cfg.id, body) : await isisConfig.create(body)
    // The passwords are write-only: the inputs empty again after a save.
    Object.assign(cfg, saved, {
      new_area_password: '',
      new_domain_password: '',
      clear_area_password: false,
      clear_domain_password: false,
    })
    cfgForm.mark()
    toast.add({ title: 'IS-IS saved; commit to apply it.', color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
  } finally {
    saving.value = false
  }
}

// The NET made from an interface's first IPv4 address (a loopback, say),
// as the server makes it: each octet as three digits, in groups of four.
const netFromIface = computed({
  get: () => !!cfg.net_interface,
  set: (on) => {
    cfg.net_interface = on ? (netIfaceItems.value[0]?.value ?? '') : ''
    if (on && !cfg.net_area) cfg.net_area = '49.0001'
  },
})
const netIfaceItems = computed(() =>
  ifaceList.value
    .filter((i) => inVrf(i.name))
    .map((i) => ({ label: ifaceText(i.name), value: i.name })),
)
const generatedNet = computed(() => {
  const ifc = ifaceList.value.find((i) => i.name === cfg.net_interface)
  const v4 = ifc?.addresses?.find((a) => /^\d+\.\d+\.\d+\.\d+\//.test(a))
  if (!v4) return ''
  const d = v4
    .split('/')[0]
    .split('.')
    .map((o) => o.padStart(3, '0'))
    .join('')
  return `${(cfg.net_area || '').trim().toLowerCase()}.${d.slice(0, 4)}.${d.slice(4, 8)}.${d.slice(8)}.00`
})

const levelItems = [
  { label: 'level-1-2 (FRR’s)', value: '' },
  { label: 'level-1', value: 'level-1' },
  { label: 'level-2-only', value: 'level-2-only' },
]
const styleItems = [
  { label: 'wide (default)', value: '' },
  { label: 'narrow', value: 'narrow' },
  { label: 'transition', value: 'transition' },
]
// Reka's select can't hold '', so '' is NONE in the selects above.
const NONE = '\u0000'
const selectItems = (items) => items.map((i) => ({ ...i, value: i.value === '' ? NONE : i.value }))
const selectModel = (key) =>
  computed({
    get: () => (cfg[key] ? cfg[key] : NONE),
    set: (v) => (cfg[key] = v === NONE ? '' : v),
  })
const level = selectModel('level')
const metricStyle = selectModel('metric_style')

const authTypes = [
  { label: 'HMAC-MD5', value: 'md5' },
  { label: 'clear text', value: 'clear' },
]
// The area (level 1) and domain (level 2) passwords.
const passwords = [
  {
    key: 'area',
    label: 'Area password',
    help: 'Authenticates the level-1 link-state packets (LSPs and SNPs). The same on every router of the area.',
  },
  {
    key: 'domain',
    label: 'Domain password',
    help: 'Authenticates the level-2 link-state packets. The same on every level-2 router.',
  },
]

const familyItems = [
  { label: 'IPv4', value: 'ipv4' },
  { label: 'IPv6', value: 'ipv6' },
]
const intoLevels = [
  { label: 'level-1', value: 'level-1' },
  { label: 'level-2', value: 'level-2' },
]
const sourceItems = [
  { label: 'connected', value: 'connected' },
  { label: 'static', value: 'static' },
  { label: 'BGP', value: 'bgp' },
  { label: 'OSPF', value: 'ospf' },
]
const routeMapItems = computed(() => [{ label: '—', value: '' }, ...objects.routeMapItems.value])
const defaultColumns = computed(() => [
  { key: 'family', label: 'Family', type: 'select', items: familyItems },
  { key: 'level', label: 'Into', type: 'select', items: intoLevels },
  { key: 'always', label: 'Always', type: 'switch' },
  { key: 'metric', label: 'Metric', type: 'number', placeholder: 'FRR’s' },
  { key: 'route_map', label: 'Route map', type: 'select', items: routeMapItems.value },
])
const redistColumns = computed(() => [
  { key: 'family', label: 'Family', type: 'select', items: familyItems },
  { key: 'source', label: 'Source', type: 'select', items: sourceItems },
  { key: 'level', label: 'Into', type: 'select', items: intoLevels },
  { key: 'metric', label: 'Metric', type: 'number', placeholder: 'FRR’s' },
  { key: 'route_map', label: 'Route map', type: 'select', items: routeMapItems.value },
])

// ----- Interfaces.
const ifaceItems = computed(() =>
  ifaceNames.value.filter(inVrf).map((n) => ({ label: ifaceText(n), value: n })),
)
const ifColumns = [
  { key: 'name', label: 'Interface', format: (i) => ifaceText(i.name) },
  {
    key: 'family',
    label: 'IP',
    format: (i) => [i.ipv4 && 'IPv4', i.ipv6 && 'IPv6'].filter(Boolean).join(', '),
  },
  { key: 'circuit_type', label: 'Circuit type', format: (i) => i.circuit_type || 'the router’s' },
  { key: 'point_to_point', label: 'Point-to-point' },
  { key: 'passive', label: 'Passive' },
  { key: 'bfd', label: 'BFD' },
  { key: 'auth', label: 'Password', format: (i) => (i.has_password ? 'yes' : '') },
  { key: 'metric', label: 'Metric', format: (i) => (i.metric ? String(i.metric) : '10') },
]
const ifFields = computed(() => [
  { key: 'name', label: 'Interface', type: 'select', items: ifaceItems.value, required: true },
  {
    key: 'ipv4',
    label: 'IPv4',
    type: 'switch',
    hint: "Runs IS-IS for the interface's IPv4 networks.",
  },
  {
    key: 'ipv6',
    label: 'IPv6',
    type: 'switch',
    hint: "Runs IS-IS for the interface's IPv6 networks.",
  },
  {
    key: 'circuit_type',
    label: 'Circuit type',
    type: 'select',
    nullable: true,
    text: true,
    items: [
      { label: 'level-1', value: 'level-1' },
      { label: 'level-1-2', value: 'level-1-2' },
      { label: 'level-2-only', value: 'level-2-only' },
    ],
    hint: "The levels of the adjacencies on the interface. Empty: the router's level.",
  },
  {
    key: 'point_to_point',
    label: 'Point-to-point',
    type: 'switch',
    hint: 'Skips the DIS election: for links and tunnels with one neighbour.',
  },
  {
    key: 'passive',
    label: 'Passive',
    type: 'switch',
    hint: "Announces the interface's networks but sends no hellos: no neighbours there.",
  },
  {
    key: 'metric',
    label: 'Metric',
    type: 'number',
    hint: '0: 10. Up to 63 with narrow metrics, 16777215 with wide.',
  },
  {
    key: 'hello_interval',
    label: 'Hello interval (s)',
    type: 'number',
    hint: '0: 3 s.',
  },
  {
    key: 'hello_multiplier',
    label: 'Hello multiplier',
    type: 'number',
    hint: 'Hellos missed before the neighbour is down; 0: 10.',
  },
  { key: 'priority', label: 'Priority', type: 'custom' },
  { key: 'password', label: 'Hello password', type: 'custom' },
  {
    key: 'bfd',
    label: 'BFD',
    type: 'switch',
    hint: 'Detects a lost neighbour with BFD, when the interface has BFD (Routing → BFD).',
  },
])
const ifDefaults = {
  name: '',
  ipv4: true,
  ipv6: false,
  circuit_type: '',
  point_to_point: false,
  passive: false,
  metric: 0,
  hello_interval: 0,
  hello_multiplier: 0,
  priority: null,
  bfd: false,
  password_type: 'md5',
  new_password: '',
}
</script>

<template>
  <div class="space-y-4">
    <div class="card">
      <FormHeader title="IS-IS">
        <UButton
          v-if="!readOnly"
          label="Save"
          :loading="saving"
          :disabled="!cfgForm.dirty()"
          @click="save"
        />
      </FormHeader>
      <p class="mb-4 max-w-3xl text-sm text-muted">
        IS-IS (IPv4 and IPv6) runs FRR's isisd in this virtual firewall. It is off until enabled
        here; changes take effect when committed. IS-IS is not IP, so no firewall rules apply to it.
        <template v-if="vrfName">
          This is VRF {{ vrfName }}'s IS-IS, on the VRF's interfaces; its routes go in the VRF's
          table.
        </template>
      </p>
      <fieldset :disabled="readOnly" class="max-w-3xl space-y-3">
        <UFormField label="Enabled" :ui="inlineField" help="Starts isisd; off stops it.">
          <USwitch v-model="cfg.enabled" />
        </UFormField>
        <UFormField
          label="NET from interface"
          :ui="inlineField"
          help="Makes the NET from an interface's IPv4 address, typically a loopback's: 192.168.1.1 becomes system id 1921.6800.1001. It follows the address on each commit."
        >
          <USwitch v-model="netFromIface" />
        </UFormField>
        <template v-if="netFromIface">
          <UFormField label="Interface" :ui="inlineField">
            <USelect v-model="cfg.net_interface" :items="netIfaceItems" class="w-72" />
          </UFormField>
          <UFormField
            label="Area"
            :ui="inlineField"
            help="The NET's area: an AFI byte (49) and more."
          >
            <UInput
              v-model="cfg.net_area"
              class="w-48"
              placeholder="49.0001"
              :ui="{ base: 'font-mono' }"
            />
          </UFormField>
          <UFormField label="NET" :ui="inlineField">
            <span v-if="generatedNet" class="font-mono text-sm">{{ generatedNet }}</span>
            <span v-else class="text-sm text-error">The interface has no static IPv4 address.</span>
          </UFormField>
        </template>
        <UFormField
          v-else
          label="NET"
          :ui="inlineField"
          help="Network entity title: the area (49.0001), the system id (unique per router; 1921.6800.1001 from 192.168.1.1) and 00."
        >
          <UInput
            v-model="cfg.net"
            class="w-72"
            placeholder="49.0001.1921.6800.1001.00"
            :ui="{ base: 'font-mono' }"
          />
        </UFormField>
        <UFormField
          v-if="store.hasPeer && cfg.net"
          label="HA peer NET"
          :ui="inlineField"
          help="The HA secondary's NET: the same area, another system id."
        >
          <UInput v-model="cfg.peer_net" class="w-72" :ui="{ base: 'font-mono' }" />
        </UFormField>
        <UFormField
          label="Level"
          :ui="inlineField"
          help="Level 1 routes inside the area, level 2 between areas."
        >
          <USelect v-model="level" :items="selectItems(levelItems)" class="w-48" />
        </UFormField>
        <UFormField
          label="Metric style"
          :ui="inlineField"
          help="Wide metrics go up to 16777215; narrow (up to 63) only for old routers."
        >
          <USelect v-model="metricStyle" :items="selectItems(styleItems)" class="w-48" />
        </UFormField>
        <UFormField
          label="IPv6 topology"
          :ui="inlineField"
          help="Multi-topology: IPv6 gets its own topology, so a link may run IPv4 or IPv6 alone. All routers must agree."
        >
          <USwitch v-model="cfg.ipv6_topology" />
        </UFormField>
        <UFormField label="Log adjacency changes" :ui="inlineField">
          <USwitch v-model="cfg.log_adjacency_changes" />
        </UFormField>
        <UFormField
          label="Overload"
          :ui="inlineField"
          help="Sets the overload bit: the other routers stop routing through this one (for maintenance)."
        >
          <USwitch v-model="cfg.overload" />
        </UFormField>

        <div class="border-b border-default pt-2 pb-1 text-sm font-semibold">Authentication</div>
        <UFormField
          v-for="p in passwords"
          :key="p.key"
          :label="p.label"
          :help="p.help"
          :ui="inlineField"
        >
          <div class="flex w-full flex-wrap items-center gap-2">
            <UInput
              v-model="cfg[`new_${p.key}_password`]"
              type="password"
              autocomplete="new-password"
              class="min-w-48 flex-1"
              :disabled="cfg[`clear_${p.key}_password`]"
              :placeholder="cfg[`has_${p.key}_password`] ? 'set; leave empty to keep it' : 'none'"
            />
            <USelect
              v-model="cfg[`${p.key}_password_type`]"
              :items="authTypes"
              class="w-36"
              :disabled="cfg[`clear_${p.key}_password`]"
            />
            <USwitch
              v-if="cfg[`has_${p.key}_password`]"
              v-model="cfg[`clear_${p.key}_password`]"
              label="Remove"
            />
          </div>
        </UFormField>

        <div class="border-b border-default pt-2 pb-1 text-sm font-semibold">Default route</div>
        <UFormField
          label="Default originate"
          :ui="inlineField"
          help="Announces a default route into a level while the routing table has one, or always."
        >
          <EntriesEditor
            v-model="cfg.default_originate"
            :columns="defaultColumns"
            :new-entry="
              () => ({ family: 'ipv4', level: 'level-2', always: false, metric: 0, route_map: '' })
            "
            :disabled="readOnly"
            add-label="Add default route"
            empty="No default route announced."
          />
        </UFormField>

        <div class="border-b border-default pt-2 pb-1 text-sm font-semibold">Redistribute</div>
        <UFormField
          label="Redistribute"
          :ui="inlineField"
          help="Announces these routes into a level. Static: the static routes (Routing → Static). OSPF: OSPFv2's into IPv4, OSPFv3's into IPv6. A route map filters or changes them."
        >
          <EntriesEditor
            v-model="cfg.redistribute"
            :columns="redistColumns"
            :new-entry="
              () => ({
                family: 'ipv4',
                source: 'connected',
                level: 'level-2',
                metric: 0,
                route_map: '',
              })
            "
            :disabled="readOnly"
            add-label="Add source"
            empty="Nothing redistributed."
          />
        </UFormField>
      </fieldset>
    </div>

    <CrudPage
      title="IS-IS interfaces"
      description="The interfaces IS-IS runs on, and their options. Link ends between virtual firewalls are interfaces too."
      :api="isisInterfaces"
      :params="{ instance_id: store.currentId }"
      :row-filter="(i) => inVrf(i.name)"
      :columns="ifColumns"
      :fields="ifFields"
      :defaults="ifDefaults"
      noun="interface"
      new-label="Add interface"
      :item-name="(i) => `IS-IS on interface ${ifaceText(i.name)}`"
    >
      <template #field-priority="{ form }">
        <UInput
          :model-value="form.priority ?? ''"
          type="number"
          class="w-28"
          placeholder="64"
          @update:model-value="(v) => (form.priority = v === '' || v == null ? null : Number(v))"
        />
        <span class="ms-2 text-sm text-muted">In the DIS election on a LAN (0-127).</span>
      </template>
      <template #field-password="{ form }">
        <div class="flex w-full flex-wrap items-center gap-2">
          <UInput
            v-model="form.new_password"
            type="password"
            autocomplete="new-password"
            class="min-w-48 flex-1"
            :disabled="form.clear_password"
            :placeholder="form.has_password ? 'set; leave empty to keep it' : 'none'"
          />
          <USelect
            v-model="form.password_type"
            :items="authTypes"
            class="w-36"
            :disabled="form.clear_password"
          />
          <USwitch v-if="form.has_password" v-model="form.clear_password" label="Remove" />
        </div>
        <span class="text-sm text-muted">
          Authenticates the hellos on the interface; the neighbour needs the same.
        </span>
      </template>
    </CrudPage>
  </div>
</template>
