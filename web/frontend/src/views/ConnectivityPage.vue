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
import { apiURL } from '@/utils/base'

// Connectivity tests: the agent sends ICMP echoes, TCP connects or UDP
// datagrams from the selected instance's namespace (POST /api/agent/probe)
// at an interval and streams each probe's result; the page keeps the
// statistics and graphs the round trips and the failures.
const toast = useToast()
const auth = useAuthStore()
const { store, ifaceNames, ifaceText } = useInstanceRefs()

const NONE = '__none__'
const form = reactive({
  protocol: 'icmp',
  interface: NONE,
  target: '',
  family: 'auto',
  port: 443,
  count: 10,
  interval: 1,
  timeout: 2,
  size: 56,
  payload: '',
})
const protocolItems = [
  { label: 'Ping (ICMP)', value: 'icmp' },
  { label: 'TCP connect', value: 'tcp' },
  { label: 'UDP', value: 'udp' },
]
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
// A port to start from per protocol: HTTPS, DNS.
watch(
  () => form.protocol,
  (p) => {
    if (p === 'tcp' && form.port === 53) form.port = 443
    if (p === 'udp' && form.port === 443) form.port = 53
  },
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
const lastTarget = ref('')
// What the agent probes: { addr, protocol, port }.
const probed = ref(null)
// The newest MAX_KEEP probes, by sequence number, for the graph and the
// table; the statistics count them all.
const MAX_KEEP = 3600
const probes = ref([])
const stats = reactive({})
let controller = null

function resetStats() {
  Object.assign(stats, {
    sent: 0,
    ok: 0,
    refused: 0,
    unreachable: 0,
    timeout: 0,
    error: 0,
    last: null,
    best: null,
    worst: null,
    sum: 0,
    sumSq: 0,
    jitterSum: 0,
    jitterN: 0,
    prevOk: null,
  })
}
resetStats()

function onEvent(ev) {
  switch (ev.type) {
    case 'error':
      toast.add({ title: ev.error, color: 'error' })
      break
    case 'target':
      probed.value = { addr: ev.addr, protocol: ev.protocol, port: ev.port }
      break
    case 'probe': {
      const p = {
        seq: ev.seq,
        at: new Date(ev.at),
        status: ev.status,
        rtt: ev.rtt_us != null ? ev.rtt_us / 1000 : null,
        from: ev.from ?? '',
        error: ev.error ?? '',
      }
      stats.sent++
      stats[p.status] = (stats[p.status] ?? 0) + 1
      if (p.status === 'ok') {
        stats.last = p.rtt
        stats.best = stats.best == null ? p.rtt : Math.min(stats.best, p.rtt)
        stats.worst = stats.worst == null ? p.rtt : Math.max(stats.worst, p.rtt)
        stats.sum += p.rtt
        stats.sumSq += p.rtt * p.rtt
        if (stats.prevOk != null) {
          stats.jitterSum += Math.abs(p.rtt - stats.prevOk)
          stats.jitterN++
        }
        stats.prevOk = p.rtt
      }
      // Results come in order but for a timeout longer than the interval.
      const list = probes.value
      let i = list.length
      while (i > 0 && list[i - 1].seq > p.seq) i--
      list.splice(i, 0, p)
      if (list.length > MAX_KEEP) list.splice(0, list.length - MAX_KEEP)
      break
    }
  }
}

async function start() {
  probes.value = []
  probed.value = null
  resetStats()
  lastTarget.value = form.target.trim()
  running.value = true
  controller = new AbortController()
  const ports = form.protocol !== 'icmp'
  try {
    const res = await fetch(apiURL('/agent/probe'), {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        instance: store.current?.name,
        interface: form.interface === NONE ? '' : form.interface,
        target: lastTarget.value,
        family: form.family === 'auto' ? '' : form.family,
        protocol: form.protocol,
        port: ports ? Number(form.port) || 0 : 0,
        count: Number(form.count) || 0,
        interval: Math.round(Number(form.interval) * 1000) || 0,
        timeout: Math.round(Number(form.timeout) * 1000) || 0,
        size: form.protocol === 'icmp' ? Number(form.size) || 0 : 0,
        payload: form.protocol === 'udp' ? form.payload : '',
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

const canStart = computed(
  () =>
    store.current &&
    auth.canEdit &&
    form.target.trim().length > 0 &&
    (form.protocol === 'icmp' || (form.port >= 1 && form.port <= 65535)),
)

const ms = (v) => (v == null ? '–' : v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : v.toFixed(0))
const failed = computed(() => stats.sent - stats.ok)
const lossPct = computed(() => (stats.sent ? (failed.value / stats.sent) * 100 : 0))
const avg = computed(() => (stats.ok ? stats.sum / stats.ok : null))
const stdev = computed(() =>
  stats.ok ? Math.sqrt(Math.max(0, stats.sumSq / stats.ok - avg.value ** 2)) : null,
)
const jitter = computed(() => (stats.jitterN ? stats.jitterSum / stats.jitterN : null))
const target = computed(() => {
  const p = probed.value
  if (!p) return lastTarget.value
  const addr = p.port
    ? p.addr.includes(':')
      ? `[${p.addr}]:${p.port}`
      : `${p.addr}:${p.port}`
    : p.addr
  return lastTarget.value !== p.addr ? `${lastTarget.value} (${addr})` : addr
})

const statusText = {
  ok: 'OK',
  refused: 'Refused',
  unreachable: 'Unreachable',
  timeout: 'Timeout',
  error: 'Error',
}
// What "ok" and "refused" mean differ by protocol.
const okText = computed(
  () => ({ icmp: 'Replies', tcp: 'Connected', udp: 'Answered' })[probed.value?.protocol] ?? 'OK',
)
const statusClass = (s) =>
  s === 'ok' ? 'text-success' : s === 'timeout' || s === 'error' ? 'text-error' : 'text-warning'
const detail = (p) =>
  p.status === 'refused'
    ? probed.value?.protocol === 'tcp'
      ? 'reset: the port is closed'
      : 'port unreachable'
    : [p.error, p.from && `from ${p.from}`].filter(Boolean).join(' ')

// The probes table, newest first.
const rows = computed(() => probes.value.toReversed())
const { search, filtered } = useSearch(
  rows,
  (p) => `${p.seq} ${p.at.toLocaleTimeString()} ${statusText[p.status]} ${ms(p.rtt)} ${detail(p)}`,
)

// The graph: each probe's round trip by sequence number, the line broken
// where one failed; a failed probe is a red line the graph's height
// (orange: refused or unreachable).
const GW = 1000
const GH = 160
function niceMax(v) {
  const steps = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000]
  return steps.find((s) => s >= v) ?? Math.ceil(v / 10000) * 10000
}
const graph = computed(() => {
  const list = probes.value
  if (!list.length) return null
  const first = list[0].seq
  const last = Math.max(list.at(-1).seq, first + 9)
  const span = last - first + 1
  const max = niceMax(Math.max(1, ...list.map((p) => p.rtt ?? 0)) * 1.1)
  const px = (seq) => ((seq - first + 0.5) / span) * GW
  const py = (v) => GH - (v / max) * GH
  let path = ''
  let pen = false
  const fails = []
  const dots = []
  for (const p of list) {
    if (p.status === 'ok') {
      path += `${pen ? 'L' : 'M'}${px(p.seq)},${py(p.rtt)}`
      pen = true
      dots.push({ x: px(p.seq), y: py(p.rtt) })
    } else {
      pen = false
      fails.push({ x: px(p.seq), hard: p.status === 'timeout' || p.status === 'error' })
    }
  }
  return {
    path,
    fails,
    // Single replies between failures have no line; show them as dots.
    dots: span <= 120 ? dots : [],
    max,
    ticks: [1, 0.75, 0.5, 0.25, 0].map((f) => f * max),
    first,
    last,
    from: list[0].at,
    to: list.at(-1).at,
    slot: GW / span,
  }
})
// Which probe the mouse is over.
const hover = ref(null)
function onMove(e) {
  const g = graph.value
  if (!g) return
  const r = e.currentTarget.getBoundingClientRect()
  const seq = g.first + Math.floor(((e.clientX - r.left) / r.width) * (g.last - g.first + 1))
  hover.value = probes.value.find((p) => p.seq === seq) ?? null
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <form class="card flex flex-wrap items-end gap-3" @submit.prevent="start">
      <UFormField label="Test">
        <USelect v-model="form.protocol" :items="protocolItems" class="w-36" :disabled="running" />
      </UFormField>
      <UFormField label="Source interface">
        <USelect v-model="form.interface" :items="ifaceItems" class="w-64" :disabled="running" />
      </UFormField>
      <UFormField label="Destination" class="min-w-64 flex-1">
        <UInput
          v-model="form.target"
          class="w-full font-mono"
          placeholder="192.0.2.1, 2001:db8::1, a named host or a DNS name"
          list="probe-hosts"
          :disabled="running"
        />
        <datalist id="probe-hosts">
          <option v-for="n in hostNames" :key="n" :value="n" />
        </datalist>
      </UFormField>
      <UFormField
        label="IP version"
        title="For a named host or DNS name with both an IPv4 and an IPv6 address"
      >
        <USelect v-model="form.family" :items="familyItems" class="w-28" :disabled="running" />
      </UFormField>
      <UFormField v-if="form.protocol !== 'icmp'" label="Port">
        <UInput
          v-model.number="form.port"
          type="number"
          min="1"
          max="65535"
          class="w-24"
          :disabled="running"
        />
      </UFormField>
      <UFormField label="Count" title="How many probes; empty or 0 keeps going until Stop">
        <UInput
          v-model="form.count"
          type="number"
          min="0"
          max="100000"
          class="w-24"
          placeholder="until Stop"
          :disabled="running"
        />
      </UFormField>
      <UFormField label="Interval (s)">
        <UInput
          v-model="form.interval"
          type="number"
          min="0.1"
          max="60"
          step="0.1"
          class="w-20"
          :disabled="running"
        />
      </UFormField>
      <UFormField label="Timeout (s)" title="How long to wait for each probe's answer">
        <UInput
          v-model="form.timeout"
          type="number"
          min="0.1"
          max="10"
          step="0.1"
          class="w-20"
          :disabled="running"
        />
      </UFormField>
      <UFormField v-if="form.protocol === 'icmp'" label="Size" title="Data bytes per echo">
        <UInput
          v-model="form.size"
          type="number"
          min="0"
          max="9000"
          class="w-20"
          :disabled="running"
        />
      </UFormField>
      <UFormField
        v-if="form.protocol === 'udp'"
        label="Payload"
        title="Text each datagram carries; the service must answer it for the probe to count"
      >
        <UInput v-model="form.payload" class="w-40 font-mono" :disabled="running" />
      </UFormField>
      <UButton v-if="!running" type="submit" icon="i-lucide-play" :disabled="!canStart"
        >Start</UButton
      >
      <UButton v-else color="error" icon="i-lucide-square" @click="stop">Stop</UButton>
    </form>

    <p v-if="form.protocol === 'udp' && !running && !stats.sent" class="text-sm text-muted">
      A UDP probe succeeds when the service answers the datagram; an ICMP port unreachable counts as
      refused. Many services ignore what they don't understand, so no answer may only mean the
      payload was wrong.
    </p>

    <div v-if="running || stats.sent" class="flex items-center gap-2 text-sm text-muted">
      <span v-if="running" class="inline-block size-2 animate-pulse rounded-full bg-primary" />
      <span>{{ store.current?.name }} → {{ target }}</span>
      <span v-if="running && !stats.sent">Probing…</span>
    </div>

    <div v-if="stats.sent" class="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
      <div class="rounded border border-default p-2">
        <div class="text-xs text-muted">Sent</div>
        <div class="font-mono text-lg">{{ stats.sent }}</div>
      </div>
      <div class="rounded border border-default p-2">
        <div class="text-xs text-muted">{{ okText }}</div>
        <div class="font-mono text-lg text-success">{{ stats.ok }}</div>
      </div>
      <div class="rounded border border-default p-2">
        <div class="text-xs text-muted">Failed</div>
        <div class="font-mono text-lg" :class="{ 'text-error': failed }">
          {{ failed }} <span class="text-sm">({{ lossPct.toFixed(1) }}%)</span>
        </div>
        <div v-if="failed" class="text-xs text-muted">
          <template v-for="s in ['timeout', 'refused', 'unreachable', 'error']" :key="s">
            <span v-if="stats[s]" class="me-2"
              >{{ statusText[s].toLowerCase() }} {{ stats[s] }}</span
            >
          </template>
        </div>
      </div>
      <div class="rounded border border-default p-2">
        <div class="text-xs text-muted">Last</div>
        <div class="font-mono text-lg">{{ ms(stats.last) }} <span class="text-sm">ms</span></div>
      </div>
      <div class="rounded border border-default p-2">
        <div class="text-xs text-muted">Average</div>
        <div class="font-mono text-lg">{{ ms(avg) }} <span class="text-sm">ms</span></div>
      </div>
      <div class="rounded border border-default p-2">
        <div class="text-xs text-muted">Best / worst</div>
        <div class="font-mono text-lg">
          {{ ms(stats.best) }} / {{ ms(stats.worst) }} <span class="text-sm">ms</span>
        </div>
      </div>
      <div class="rounded border border-default p-2">
        <div class="text-xs text-muted">Std. deviation</div>
        <div class="font-mono text-lg">{{ ms(stdev) }} <span class="text-sm">ms</span></div>
      </div>
      <div class="rounded border border-default p-2" title="The mean change between replies">
        <div class="text-xs text-muted">Jitter</div>
        <div class="font-mono text-lg">{{ ms(jitter) }} <span class="text-sm">ms</span></div>
      </div>
    </div>

    <div v-if="graph" class="rounded border border-default p-2">
      <div class="mb-1 flex flex-wrap justify-between gap-2 text-xs text-muted">
        <span v-if="hover" class="font-mono">
          #{{ hover.seq }} · {{ hover.at.toLocaleTimeString() }} ·
          <span :class="statusClass(hover.status)">{{ statusText[hover.status] }}</span>
          <template v-if="hover.rtt != null"> · {{ ms(hover.rtt) }} ms</template>
          <template v-if="detail(hover)"> · {{ detail(hover) }}</template>
        </span>
        <span v-else>
          Round trip, probes {{ graph.first }}–{{ graph.last }} ({{
            graph.from.toLocaleTimeString()
          }}–{{ graph.to.toLocaleTimeString() }})
        </span>
        <span class="flex gap-3">
          <span class="flex items-center gap-1"
            ><span class="inline-block h-0.5 w-4 bg-primary" />round trip</span
          >
          <span class="flex items-center gap-1"
            ><span class="inline-block h-3 w-0.5 bg-error" />timeout</span
          >
          <span class="flex items-center gap-1"
            ><span class="inline-block h-3 w-0.5 bg-warning" />refused / unreachable</span
          >
        </span>
      </div>
      <div class="flex gap-2">
        <div class="flex flex-col justify-between text-right font-mono text-xs text-muted">
          <span v-for="(t, i) in graph.ticks" :key="i">{{ t }} ms</span>
        </div>
        <svg
          class="block flex-1"
          :height="GH"
          :viewBox="`0 0 ${GW} ${GH}`"
          preserveAspectRatio="none"
          @mousemove="onMove"
          @mouseleave="hover = null"
        >
          <line
            v-for="(t, i) in graph.ticks"
            :key="i"
            x1="0"
            :x2="GW"
            :y1="GH - (t / graph.max) * GH"
            :y2="GH - (t / graph.max) * GH"
            class="stroke-(--ui-border)"
            vector-effect="non-scaling-stroke"
          />
          <rect
            v-for="(f, i) in graph.fails"
            :key="i"
            :x="f.x - graph.slot / 2"
            y="0"
            :width="graph.slot"
            :height="GH"
            :class="f.hard ? 'fill-error/15' : 'fill-warning/15'"
          />
          <line
            v-for="(f, i) in graph.fails"
            :key="`l${i}`"
            :x1="f.x"
            :x2="f.x"
            y1="0"
            :y2="GH"
            :class="f.hard ? 'stroke-error' : 'stroke-warning'"
            vector-effect="non-scaling-stroke"
          />
          <path
            :d="graph.path"
            fill="none"
            class="stroke-primary"
            stroke-width="1.5"
            vector-effect="non-scaling-stroke"
          />
          <line
            v-for="(d, i) in graph.dots"
            :key="`d${i}`"
            :x1="d.x"
            :x2="d.x"
            :y1="d.y"
            :y2="d.y"
            class="stroke-primary"
            stroke-width="5"
            stroke-linecap="round"
            vector-effect="non-scaling-stroke"
          />
          <line
            v-if="hover"
            :x1="((hover.seq - graph.first + 0.5) / (graph.last - graph.first + 1)) * GW"
            :x2="((hover.seq - graph.first + 0.5) / (graph.last - graph.first + 1)) * GW"
            y1="0"
            :y2="GH"
            class="stroke-(--ui-text-muted)"
            stroke-dasharray="3 3"
            vector-effect="non-scaling-stroke"
          />
        </svg>
      </div>
    </div>

    <div v-if="probes.length" class="flex flex-col gap-2">
      <h3 class="font-semibold">
        Probes<span v-if="stats.sent > probes.length" class="font-normal text-muted">
          (the last {{ probes.length }})</span
        >
      </h3>
      <SearchInput v-model="search" />
      <div class="overflow-x-auto rounded border border-default">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-muted">
              <th class="px-2 py-1 text-right">#</th>
              <th class="px-2 py-1">Sent</th>
              <th class="px-2 py-1">Result</th>
              <th class="px-2 py-1 text-right">Round trip</th>
              <th class="px-2 py-1">Details</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in filtered" :key="p.seq" class="border-t border-default">
              <td class="px-2 py-1 text-right font-mono">{{ p.seq }}</td>
              <td class="px-2 py-1">{{ p.at.toLocaleTimeString() }}</td>
              <td class="px-2 py-1" :class="statusClass(p.status)">{{ statusText[p.status] }}</td>
              <td class="px-2 py-1 text-right font-mono">
                {{ p.rtt != null ? `${ms(p.rtt)} ms` : '' }}
              </td>
              <td class="px-2 py-1">{{ detail(p) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
