<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { addressObjects } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useSearch } from '@/utils/search'
import { useAuthStore } from '@/stores/auth'
import SearchInput from '@/components/SearchInput.vue'

// Traceroute like MTR: mtr runs on the firewall in the selected instance's
// namespace (POST /api/agent/trace) and streams one event per probe sent,
// hop address and reply; the page keeps the statistics per hop.
const toast = useToast()
const auth = useAuthStore()
const { store, ifaceNames, ifaceText } = useInstanceRefs()

const NONE = '__none__'
const form = reactive({ interface: NONE, target: '', family: 'auto', count: 10 })
const ifaceItems = computed(() => [
  { label: 'None (the routing table decides)', value: NONE },
  ...ifaceNames.value.map((n) => ({ label: ifaceText(n), value: n })),
])
const familyItems = [
  { label: 'Auto', value: 'auto' },
  { label: 'IPv4', value: 'ipv4' },
  { label: 'IPv6', value: 'ipv6' },
]
watch(
  () => store.currentId,
  () => (form.interface = NONE),
)

// Named hosts: objects whose addresses are all single addresses.
const hostNames = ref([])
addressObjects
  .list()
  .then((list) => {
    hostNames.value = list
      .filter((o) => o.addresses?.length && o.addresses.every((a) => !a.includes('/')))
      .map((o) => o.name)
      .sort()
  })
  .catch(() => {})

const running = ref(false)
const resolved = ref('')
const lastTarget = ref('')
// Reverse DNS names of the hops' addresses, as the agent finds them.
const names = ref({})
const hops = ref([])
let controller = null
const MAX_SAMPLES = 3600

function hop(n) {
  while (hops.value.length < n) {
    hops.value.push({
      hop: hops.value.length + 1,
      addrs: [],
      sent: 0,
      recv: 0,
      last: null,
      best: null,
      worst: null,
      sum: 0,
      sumSq: 0,
      samples: [], // { seq, t, rtt } per probe, for the time graph
    })
  }
  return hops.value[n - 1]
}

function onEvent(ev) {
  if (ev.type === 'error') {
    toast.add({ title: ev.error, color: 'error' })
    return
  }
  if (ev.type === 'target') {
    resolved.value = ev.addr
    return
  }
  if (ev.type === 'name') {
    names.value = { ...names.value, [ev.addr]: ev.name }
    return
  }
  if (!ev.hop) return
  const h = hop(ev.hop)
  if (ev.type === 'sent') {
    h.sent++
    h.samples.push({ seq: ev.seq, t: Date.now(), rtt: null })
    if (h.samples.length > MAX_SAMPLES) h.samples.shift()
  } else if (ev.type === 'host' && !h.addrs.includes(ev.addr)) h.addrs.push(ev.addr)
  else if (ev.type === 'reply') {
    const ms = ev.rtt_us / 1000
    h.recv++
    h.last = ms
    h.best = h.best == null ? ms : Math.min(h.best, ms)
    h.worst = h.worst == null ? ms : Math.max(h.worst, ms)
    h.sum += ms
    h.sumSq += ms * ms
    for (let i = h.samples.length - 1; i >= 0; i--) {
      if (h.samples[i].seq === ev.seq) {
        h.samples[i].rtt = ms
        break
      }
    }
  }
}

async function start() {
  hops.value = []
  selectedHop.value = null
  resolved.value = ''
  lastTarget.value = form.target.trim()
  names.value = {}
  running.value = true
  controller = new AbortController()
  try {
    const res = await fetch('/api/agent/trace', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        instance: store.current?.name,
        interface: form.interface === NONE ? '' : form.interface,
        target: form.target.trim(),
        family: form.family === 'auto' ? '' : form.family,
        count: Number(form.count) || 0,
      }),
      signal: controller.signal,
    })
    if (!res.ok) {
      let msg = res.statusText
      try {
        msg = (await res.json()).error ?? msg
      } catch {
        /* not JSON */
      }
      throw new Error(msg)
    }
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
    let rest = ''
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      rest += value
      const lines = rest.split('\n')
      rest = lines.pop()
      for (const l of lines) if (l.trim()) onEvent(JSON.parse(l))
    }
  } catch (err) {
    if (err.name !== 'AbortError') toast.add({ title: err.message, color: 'error' })
  } finally {
    running.value = false
    controller = null
  }
}
const stop = () => controller?.abort()
onBeforeUnmount(stop)

// Hops past the one the target answers on are not shown.
const rows = computed(() => {
  const end = hops.value.findIndex((h) => h.addrs.includes(resolved.value))
  const list = end >= 0 ? hops.value.slice(0, end + 1) : hops.value
  return list.map((h) => {
    const avg = h.recv ? h.sum / h.recv : null
    const lossPct = h.sent ? (1 - Math.min(h.recv, h.sent) / h.sent) * 100 : null
    return {
      hop: h.hop,
      host: h.addrs.length ? h.addrs.join(', ') : '???',
      name: h.addrs
        .map((a) => names.value[a])
        .filter(Boolean)
        .join(', '),
      lossPct,
      loss: lossPct == null ? '' : `${lossPct.toFixed(0)}%`,
      sent: h.sent,
      lastMs: h.last,
      avgMs: avg,
      bestMs: h.best,
      worstMs: h.worst,
      last: ms(h.last),
      avg: ms(avg),
      best: ms(h.best),
      worst: ms(h.worst),
      stdev: ms(h.recv ? Math.sqrt(Math.max(0, h.sumSq / h.recv - avg * avg)) : null),
    }
  })
})
const ms = (v) => (v == null ? '' : v.toFixed(1))
const { search, filtered } = useSearch(rows, (r) => `${r.hop} ${r.host} ${r.name}`)

// The trace graph (PingPlotter's): one row per hop on a shared ms scale,
// the best-worst range as a bar, the average as a tick, and a line through
// the hops' averages. The scale is a round number above the worst average.
const ROW = 20
const GW = 1000 // the graph's viewBox width; it is stretched to the cell
function niceMax(v) {
  const steps = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000]
  return steps.find((s) => s >= v) ?? Math.ceil(v / 10000) * 10000
}
const scale = computed(() => {
  const m = Math.max(0, ...filtered.value.map((r) => r.avgMs ?? 0))
  return niceMax(m * 1.25 || 1)
})
const x = (v) => (Math.min(v, scale.value) / scale.value) * GW
const ticks = computed(() => [0, 0.25, 0.5, 0.75, 1].map((f) => f * scale.value))
const avgLine = computed(() =>
  filtered.value
    .map((r, i) => (r.avgMs == null ? null : `${x(r.avgMs)},${i * ROW + ROW / 2}`))
    .filter(Boolean)
    .join(' '),
)
const latencyClass = (v) =>
  v == null ? '' : v < 50 ? 'fill-success' : v < 150 ? 'fill-warning' : 'fill-error'

// The time graph: the selected hop (the last by default), each probe's
// round trip over time; a probe with no reply after 3 s is lost (red).
const selectedHop = ref(null)
const graphHop = computed(
  () => hops.value[(selectedHop.value ?? rows.value.at(-1)?.hop ?? 0) - 1] ?? null,
)
const TW = 1000
const TH = 120
const timeline = computed(() => {
  const h = graphHop.value
  if (!h || !h.samples.length) return null
  const now = Date.now()
  const t0 = h.samples[0].t
  const span = Math.max(10_000, now - t0)
  const max = niceMax(Math.max(1, ...h.samples.map((s) => s.rtt ?? 0)) * 1.1)
  const tx = (t) => ((t - t0) / span) * TW
  const ty = (v) => TH - (v / max) * TH
  const pts = []
  const lost = []
  for (const s of h.samples) {
    if (s.rtt != null) pts.push(`${tx(s.t)},${ty(s.rtt)}`)
    else if (now - s.t > 3000) lost.push(tx(s.t))
  }
  return { pts: pts.join(' '), lost, max, span }
})
// Redraws the time graph while running, so probes become lost on time.
const tick = ref(0)
const ticker = setInterval(() => running.value && tick.value++, 1000)
onBeforeUnmount(() => clearInterval(ticker))
const timelineNow = computed(() => (tick.value, timeline.value))
</script>

<template>
  <div class="flex flex-col gap-3">
    <form class="card flex flex-wrap items-end gap-3" @submit.prevent="start">
      <UFormField label="Source interface">
        <USelect v-model="form.interface" :items="ifaceItems" class="w-64" :disabled="running" />
      </UFormField>
      <UFormField label="Destination" class="min-w-64 flex-1">
        <UInput
          v-model="form.target"
          class="w-full font-mono"
          placeholder="192.0.2.1, 2001:db8::1, a named host or a DNS name"
          list="trace-hosts"
          :disabled="running"
        />
        <datalist id="trace-hosts">
          <option v-for="n in hostNames" :key="n" :value="n" />
        </datalist>
      </UFormField>
      <UFormField
        label="IP version"
        title="For a named host or DNS name with both an IPv4 and an IPv6 address"
      >
        <USelect v-model="form.family" :items="familyItems" class="w-28" :disabled="running" />
      </UFormField>
      <UFormField label="Rounds">
        <UInput
          v-model="form.count"
          type="number"
          min="1"
          max="3600"
          class="w-24"
          :disabled="running"
        />
      </UFormField>
      <UButton
        v-if="!running"
        type="submit"
        icon="i-lucide-play"
        :disabled="!store.current || !form.target.trim() || !auth.canEdit"
        >Start</UButton
      >
      <UButton v-else color="error" icon="i-lucide-square" @click="stop">Stop</UButton>
    </form>

    <div class="flex flex-wrap items-center gap-3">
      <SearchInput v-model="search" />
      <span v-if="resolved" class="text-sm text-muted">
        <span
          v-if="running"
          class="me-1 inline-block size-2 animate-pulse rounded-full bg-primary"
        />
        {{ store.current?.name }} →
        {{ lastTarget !== resolved ? `${lastTarget} (${resolved})` : resolved }}
      </span>
    </div>

    <div class="overflow-x-auto rounded border border-default">
      <table class="trace w-full font-mono text-xs">
        <thead>
          <tr class="text-muted">
            <th class="w-8 text-right">Hop</th>
            <th class="text-left">Host</th>
            <th class="text-left">Name</th>
            <th class="w-12 text-right">Loss</th>
            <th class="w-10 text-right">Sent</th>
            <th class="w-14 text-right">Last</th>
            <th class="w-14 text-right">Avg</th>
            <th class="w-14 text-right">Best</th>
            <th class="w-14 text-right">Worst</th>
            <th class="w-14 text-right">StDev</th>
            <th class="min-w-64 graph-head">
              <div class="relative h-4">
                <span
                  v-for="(t, i) in ticks"
                  :key="i"
                  class="absolute -translate-x-1/2 font-normal"
                  :class="{
                    '-translate-x-full!': i === ticks.length - 1,
                    'translate-x-0!': i === 0,
                  }"
                  :style="{ left: `${(i / (ticks.length - 1)) * 100}%` }"
                  >{{ t }} ms</span
                >
              </div>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(r, i) in filtered"
            :key="r.hop"
            class="cursor-pointer hover:bg-elevated"
            :class="{ 'bg-accented': graphHop?.hop === r.hop }"
            :style="{ height: `${ROW}px` }"
            title="Show this hop in the time graph"
            @click="selectedHop = r.hop"
          >
            <td class="text-right">{{ r.hop }}</td>
            <td class="max-w-80 truncate">{{ r.host }}</td>
            <td class="max-w-80 truncate" :title="r.name">{{ r.name }}</td>
            <td class="text-right" :class="{ 'font-bold text-error': r.lossPct > 0 }">
              {{ r.loss }}
            </td>
            <td class="text-right">{{ r.sent }}</td>
            <td class="text-right">{{ r.last }}</td>
            <td class="text-right">{{ r.avg }}</td>
            <td class="text-right">{{ r.best }}</td>
            <td class="text-right">{{ r.worst }}</td>
            <td class="text-right">{{ r.stdev }}</td>
            <td v-if="i === 0" :rowspan="filtered.length" class="graph-cell">
              <svg
                class="block w-full"
                :height="filtered.length * ROW"
                :viewBox="`0 0 ${GW} ${filtered.length * ROW}`"
                preserveAspectRatio="none"
              >
                <line
                  v-for="(t, k) in ticks"
                  :key="k"
                  :x1="x(t)"
                  :x2="x(t)"
                  y1="0"
                  :y2="filtered.length * ROW"
                  class="stroke-(--ui-border)"
                  vector-effect="non-scaling-stroke"
                />
                <g v-for="(h, k) in filtered" :key="h.hop">
                  <rect
                    v-if="h.lossPct > 0"
                    x="0"
                    :y="k * ROW + 2"
                    :width="(h.lossPct / 100) * GW"
                    :height="ROW - 4"
                    class="fill-error/15"
                  />
                  <rect
                    v-if="h.bestMs != null"
                    :x="x(h.bestMs)"
                    :y="k * ROW + ROW / 2 - 3"
                    :width="Math.max(2, x(h.worstMs) - x(h.bestMs))"
                    height="6"
                    :class="latencyClass(h.avgMs)"
                    opacity="0.45"
                  />
                  <rect
                    v-if="h.avgMs != null"
                    :x="x(h.avgMs) - 2"
                    :y="k * ROW + 3"
                    width="4"
                    :height="ROW - 6"
                    :class="latencyClass(h.avgMs)"
                  />
                </g>
                <polyline
                  :points="avgLine"
                  fill="none"
                  class="stroke-error"
                  stroke-width="1.5"
                  vector-effect="non-scaling-stroke"
                />
              </svg>
            </td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="11" class="py-3 text-center text-muted">
              {{ running ? 'Waiting for replies…' : 'No hops yet.' }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="timelineNow" class="rounded border border-default p-2">
      <div class="mb-1 flex justify-between text-xs text-muted">
        <span>Hop {{ graphHop.hop }} · {{ graphHop.addrs.join(', ') || '???' }}</span>
        <span>last {{ Math.round(timelineNow.span / 1000) }} s · red: lost</span>
      </div>
      <div class="flex gap-2">
        <div class="flex flex-col justify-between text-right font-mono text-xs text-muted">
          <span>{{ timelineNow.max }} ms</span><span>0</span>
        </div>
        <svg
          class="block flex-1"
          :height="TH"
          :viewBox="`0 0 ${TW} ${TH}`"
          preserveAspectRatio="none"
        >
          <line
            v-for="lx in timelineNow.lost"
            :key="lx"
            :x1="lx"
            :x2="lx"
            y1="0"
            :y2="TH"
            class="stroke-error"
            vector-effect="non-scaling-stroke"
          />
          <polyline
            :points="timelineNow.pts"
            fill="none"
            class="stroke-primary"
            stroke-width="1.5"
            vector-effect="non-scaling-stroke"
          />
        </svg>
      </div>
    </div>
  </div>
</template>

<style scoped>
.trace th,
.trace td {
  padding: 0 0.4rem;
  line-height: 20px;
  white-space: nowrap;
}
.trace thead th {
  border-bottom: 1px solid var(--ui-border);
  padding-top: 2px;
  padding-bottom: 2px;
}
.trace .graph-cell {
  padding: 0;
  vertical-align: top;
  border-left: 1px solid var(--ui-border);
}
.trace .graph-head {
  padding-left: 0;
  padding-right: 0;
  border-left: 1px solid var(--ui-border);
}
</style>
