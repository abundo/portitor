<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { rateLimits } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'

const { store } = useInstanceRefs()
// Police counts packets or Mbit/s, shape Mbit/s or kbit/s; always per
// second.
const unitsFor = {
  police: [
    { label: 'Mbit/s', value: 'mbit' },
    { label: 'packets/s', value: 'packets' },
  ],
  shape: [
    { label: 'Mbit/s', value: 'mbit' },
    { label: 'kbit/s', value: 'kbit' },
  ],
}
const modes = [
  { label: 'Police: drop what is over the rate', value: 'police' },
  { label: 'Shape: queue what is over the rate', value: 'shape' },
]
const isPolice = (f) => f.mode === 'police'
const unitLabel = { packets: 'packets/s', mbit: 'Mbit/s', kbit: 'kbit/s' }
const unitText = (r) => unitLabel[r.unit] ?? `${r.unit}/s`
const modeText = (r) => (r.shape ? 'shape' : 'police')
function scopeText(r) {
  if (r.shape) return 'connections, shared'
  return `${r.connections ? 'connections' : 'packets the rule matches'}, ${r.per_source ? 'per source address' : 'shared'}`
}
const rateText = (r) =>
  r.per && r.per !== 'second' ? `${r.rate} ${r.unit}/${r.per}` : `${r.rate} ${unitText(r)}`
// A new mode keeps the unit when it has it, else takes Mbit/s.
function setMode(form, mode) {
  form.mode = mode
  if (!unitsFor[mode].some((u) => u.value === form.unit)) form.unit = 'mbit'
}

// Selects can't hold '' values: packets is '' in the API, and the mode is
// the shape flag.
const api = {
  ...rateLimits,
  list: async (p) => (await rateLimits.list(p)).map(fromApi),
  create: (b) => rateLimits.create(clean(b)),
  update: async (id, b) => fromApi(await rateLimits.update(id, clean(b))),
}
function fromApi(r) {
  return { ...r, unit: r.unit || 'packets', mode: r.shape ? 'shape' : 'police' }
}
function clean(b) {
  const shape = b.mode === 'shape'
  const body = { ...b, shape, unit: b.unit === 'packets' ? '' : b.unit, per: 'second' }
  delete body.mode
  return body
}

const columns = [
  { key: 'name', label: 'Rate limit', class: 'font-medium' },
  { key: 'mode', label: 'Mode' },
  { key: 'rate', label: 'Rate' },
  { key: 'burst', label: 'Burst' },
  { key: 'per_source', label: 'Applies to' },
  { key: 'description', label: 'Description' },
]
const fields = [
  { key: 'name', label: 'Name', required: true, placeholder: 'ssh' },
  { key: 'description', label: 'Description' },
  {
    key: 'mode',
    label: 'Mode',
    type: 'custom',
    hint: 'Police drops what is over the rate. Shape queues it, so the connections slow down without losing packets; accept rules only.',
  },
  {
    key: 'connections',
    label: 'Whole connections',
    type: 'switch',
    show: isPolice,
    hint: 'On: polices all the traffic, both ways, of the connections the rules accept (accept rules only). Off: only the packets the rule matches, which on an accept rule are the new connections; Mbit/s needs whole connections.',
  },
  { key: 'rate', label: 'Rate', type: 'number', required: true },
  {
    key: 'unit',
    label: 'Unit',
    type: 'select',
    items: (f) => unitsFor[f.mode] ?? unitsFor.police,
  },
  {
    key: 'burst',
    label: 'Burst',
    type: 'number',
    show: isPolice,
    hint: 'The size of the bucket: what is allowed at once above the rate, in the same unit; 0 is the default.',
  },
  {
    key: 'per_source',
    label: 'Per source address',
    type: 'switch',
    show: isPolice,
    hint: 'Each source address (for connections: the address that opened it) gets its own limit; off, all the traffic shares one.',
  },
]
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Rate limits"
      description="Rates a rule can name (Rate limit in the rule's form). When the rule matches, its traffic goes through the rate limit. Police drops what is over the rate, in Mbit/s or packets per second: of the whole connections the rule accepts, both ways, or only of the packets the rule matches (on an accept rule, the new connections, as against SSH or ping floods). Shape queues the traffic of the connections the rule accepts to the rate, each way, where it leaves the firewall. Rules that name the same rate limit share it."
      :api="api"
      :params="{ instance_id: store.currentId }"
      :columns="columns"
      :fields="fields"
      :defaults="{
        mode: 'police',
        rate: 10,
        unit: 'mbit',
        per: 'second',
        burst: 0,
        per_source: false,
        connections: true,
      }"
      new-label="New rate limit"
      :search-text="(r) => `${modeText(r)} ${rateText(r)} ${scopeText(r)}`"
    >
      <template #field-mode="{ form }">
        <USelect
          :model-value="form.mode"
          :items="modes"
          class="w-full"
          @update:model-value="setMode(form, $event)"
        />
      </template>
      <template #cell-mode="{ row }">{{ modeText(row) }}</template>
      <template #cell-rate="{ row }">{{ rateText(row) }}</template>
      <template #cell-burst="{ row }">{{
        row.shape ? '' : row.burst ? `${row.burst} ${unitText(row)}` : 'default'
      }}</template>
      <template #cell-per_source="{ row }">{{ scopeText(row) }}</template>
    </CrudPage>
  </NeedInstance>
</template>
