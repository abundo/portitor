<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { ref } from 'vue'
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { api as backend, rateLimits } from '@/api'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { bitRate, bytes } from '@/utils/bytes'

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
const isService = (f) => !!f.service
const unitLabel = { packets: 'packets/s', mbit: 'Mbit/s', kbit: 'kbit/s' }
const unitText = (r) => unitLabel[r.unit] ?? `${r.unit}/s`
const modeText = (r) => (r.shape ? 'shape' : 'police')
// A service's own rate limit (DNS, DHCP, NTP) polices every packet that
// comes in to it, while its page switches it on.
const serviceLabel = { dns: 'DNS server', dhcp: 'DHCP server', ntp: 'NTP server' }
function scopeText(r) {
  if (r.service)
    return `all that comes in to the ${serviceLabel[r.service] ?? r.service}${r.per_source ? ', per source address' : ', shared'}`
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

// Traffic per rate limit name of the selected instance since the last
// deploy (agentapi.RateLimitStats), polled every 5 seconds while the page
// is open and visible; null when the agent can't be reached. rates holds
// what changed since the previous poll, per second: in and out bytes,
// dropped packets; none for a counter that went down (a deploy reset it).
const stats = ref(null)
const rates = ref({})
const statsLoading = ref(false)
let prev = {}
async function loadStats() {
  statsLoading.value = true
  const r = await backend.agentRateLimits().catch(() => null)
  statsLoading.value = false
  const now = Date.now()
  const mine = r ? (r.instances?.[store.current?.name] ?? {}) : null
  const next = {}
  const out = {}
  for (const [name, st] of Object.entries(mine ?? {})) {
    const cur = { t: now, in: st.orig_bytes, out: st.reply_bytes, drop: droppedPackets(st) }
    const p = prev[name]
    if (p && now > p.t && cur.in >= p.in && cur.out >= p.out && cur.drop >= p.drop) {
      const dt = (now - p.t) / 1000
      out[name] = {
        in: (cur.in - p.in) / dt,
        out: (cur.out - p.out) / dt,
        drop: (cur.drop - p.drop) / dt,
      }
    }
    next[name] = cur
  }
  prev = next
  stats.value = mine
  rates.value = out
}
const autoStats = useAutoRefresh(loadStats, { seconds: 5 })

const statOf = (r) => stats.value?.[r.name]
// A shaper drops in its queues, one per interface it sends on.
const droppedPackets = (st) =>
  st.drop_packets + (st.interfaces ?? []).reduce((n, c) => n + c.drops, 0)
const perSecond = (n) => `${n < 10 ? n.toFixed(1) : Math.round(n).toLocaleString()} packets/s`
function notCounted(r) {
  if (!stats.value) return 'Agent not reachable'
  return statOf(r) ? '' : 'Not deployed'
}
function trafficTitle(r) {
  const st = statOf(r)
  if (!st) return notCounted(r)
  return [
    `In: ${st.orig_bytes.toLocaleString()} bytes, ${st.orig_packets.toLocaleString()} packets from the side that opened the connections`,
    `Out: ${st.reply_bytes.toLocaleString()} bytes, ${st.reply_packets.toLocaleString()} packets of replies`,
    'of the rules that name it, since the last deploy; the rate over the last 5 seconds',
  ].join('\n')
}
function dropTitle(r) {
  const st = statOf(r)
  if (!st) return notCounted(r)
  if (!r.shape) {
    return `${st.drop_bytes.toLocaleString()} bytes, ${st.drop_packets.toLocaleString()} packets over the rate dropped since the last deploy`
  }
  const lines = (st.interfaces ?? []).map(
    (c) =>
      `${c.interface}: ${c.drops.toLocaleString()} dropped, held back ${c.overlimits.toLocaleString()} times, ${bytes(c.backlog)} queued`,
  )
  return [...lines, 'by the queues since the last deploy'].join('\n')
}
// A shaper's queue on each interface it sends on, for its form.
const classesOf = (r) => (r ? (statOf(r)?.interfaces ?? []) : [])
const classTotal = (r) => classesOf(r).reduce((n, c) => n + c.bytes, 0)

const columns = [
  { key: 'name', label: 'Rate limit', class: 'font-medium' },
  { key: 'mode', label: 'Mode' },
  { key: 'rate', label: 'Rate' },
  { key: 'burst', label: 'Burst' },
  { key: 'per_source', label: 'Applies to' },
  { key: 'traffic', label: 'Traffic' },
  { key: 'dropped', label: 'Dropped' },
  { key: 'description', label: 'Description' },
]
const fields = [
  { key: 'name', label: 'Name', required: true, placeholder: 'ssh' },
  { key: 'description', label: 'Description' },
  {
    key: 'mode',
    label: 'Mode',
    type: 'custom',
    show: (f) => !isService(f),
    hint: 'Police drops what is over the rate. Shape queues it, so the connections slow down without losing packets; accept rules only.',
  },
  {
    key: 'connections',
    label: 'Whole connections',
    type: 'switch',
    show: (f) => isPolice(f) && !isService(f),
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
      description="Rates a rule can name (Rate limit in the rule's form). When the rule matches, its traffic goes through the rate limit. Police drops what is over the rate, in Mbit/s or packets per second: of the whole connections the rule accepts, both ways, or only of the packets the rule matches (on an accept rule, the new connections, as against SSH or ping floods). Shape queues the traffic of the connections the rule accepts to the rate, each way, where it leaves the firewall. Rules that name the same rate limit share it. The DNS, DHCP and NTP servers each have one of their own, 1 Mbit/s to start with, which polices every packet that comes in to them while Rate limit is on on their page."
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
      <template #toolbar>
        <AutoRefreshButton :auto="autoStats" :loading="statsLoading" />
      </template>
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
      <template #cell-traffic="{ row }">
        <div v-if="statOf(row)" class="text-xs whitespace-nowrap" :title="trafficTitle(row)">
          <div>
            <span class="text-muted">in</span> {{ bytes(statOf(row).orig_bytes) }}
            <span v-if="rates[row.name]" class="text-muted"
              >· {{ bitRate(rates[row.name].in) }}</span
            >
          </div>
          <div>
            <span class="text-muted">out</span> {{ bytes(statOf(row).reply_bytes) }}
            <span v-if="rates[row.name]" class="text-muted"
              >· {{ bitRate(rates[row.name].out) }}</span
            >
          </div>
        </div>
        <span v-else class="text-xs text-muted">{{ notCounted(row) }}</span>
      </template>
      <template #cell-dropped="{ row }">
        <div v-if="statOf(row)" class="text-xs whitespace-nowrap" :title="dropTitle(row)">
          {{ droppedPackets(statOf(row)).toLocaleString() }} packets
          <div v-if="rates[row.name]?.drop" class="text-muted">
            {{ perSecond(rates[row.name].drop) }}
          </div>
        </div>
      </template>
      <template #form-extra="{ editing }">
        <div v-if="editing?.shape && classesOf(editing).length" class="text-sm">
          <div class="mb-1 font-medium">Queues since the last deploy</div>
          <table class="w-full">
            <thead class="text-left text-muted">
              <tr>
                <th class="py-1 pr-3 font-normal">Interface</th>
                <th class="py-1 pr-3 font-normal">Sent</th>
                <th class="py-1 pr-3 font-normal">Packets</th>
                <th class="py-1 pr-3 font-normal" title="Packets dropped by the queue">Dropped</th>
                <th
                  class="py-1 pr-3 font-normal"
                  title="Times a packet was held back over the rate"
                >
                  Held back
                </th>
                <th class="py-1 font-normal" title="What is queued now">Queued</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="c in classesOf(editing)" :key="c.interface">
                <td class="py-1 pr-3 font-mono">{{ c.interface }}</td>
                <td class="py-1 pr-3">{{ bytes(c.bytes) }}</td>
                <td class="py-1 pr-3">{{ c.packets.toLocaleString() }}</td>
                <td class="py-1 pr-3">{{ c.drops.toLocaleString() }}</td>
                <td class="py-1 pr-3">{{ c.overlimits.toLocaleString() }}</td>
                <td class="py-1">{{ bytes(c.backlog) }} ({{ c.qlen }})</td>
              </tr>
            </tbody>
          </table>
          <p class="mt-1 text-xs text-muted">
            The rate applies on each interface: {{ bytes(classTotal(editing)) }} sent in all.
          </p>
        </div>
      </template>
    </CrudPage>
  </NeedInstance>
</template>
