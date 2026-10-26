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

// iperf3 runs on the firewall in the selected instance's namespace
// (POST /api/agent/iperf), as a client to a server or as a server that
// the instance's ruleset opens while it runs. It streams one event per
// test start, second (interval) and end; the page keeps them per test.
const toast = useToast()
const auth = useAuthStore()
const { store, ifaceNames, ifaceText } = useInstanceRefs()

const NONE = '__none__'
const form = reactive({
  mode: 'client',
  interface: NONE,
  target: '',
  family: 'auto',
  port: 5201,
  protocol: 'tcp',
  direction: 'send',
  streams: 1,
  duration: 10,
  bitrate: '',
  listen: 600,
  oneOff: false,
})
const modeItems = [
  { label: 'Client', value: 'client' },
  { label: 'Server', value: 'server' },
]
const ifaceItems = computed(() => [
  {
    label: form.mode === 'server' ? 'Any' : 'None (the routing table decides)',
    value: NONE,
  },
  ...ifaceNames.value.map((n) => ({ label: ifaceText(n), value: n })),
])
const familyItems = computed(() => [
  { label: form.mode === 'server' ? 'Both' : 'Auto', value: 'auto' },
  { label: 'IPv4', value: 'ipv4' },
  { label: 'IPv6', value: 'ipv6' },
])
const protocolItems = [
  { label: 'TCP', value: 'tcp' },
  { label: 'UDP', value: 'udp' },
]
const directionItems = [
  { label: 'Send (upload)', value: 'send' },
  { label: 'Receive (download)', value: 'receive' },
  { label: 'Both', value: 'both' },
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
const runMode = ref('')
const listening = ref(0)
const lastTarget = ref('')
// The tests run: a client's one, or each a server takes.
const tests = ref([])
const selected = ref(null)
let controller = null

function onEvent(ev) {
  switch (ev.type) {
    case 'error':
      toast.add({ title: `iperf3: ${ev.error}`, color: 'error' })
      break
    case 'listening':
      listening.value = ev.port
      break
    case 'start':
      tests.value.push({
        n: tests.value.length + 1,
        at: new Date(),
        remote: ev.remote ?? '',
        protocol: ev.protocol ?? '',
        streams: ev.streams ?? 1,
        duration: ev.duration ?? 0,
        intervals: [],
        sums: null,
      })
      selected.value = null
      break
    case 'interval':
      tests.value.at(-1)?.intervals.push(...(ev.sums ?? []))
      break
    case 'end': {
      const t = tests.value.at(-1)
      if (t) t.sums = ev.sums ?? []
      break
    }
  }
}

async function start() {
  tests.value = []
  selected.value = null
  listening.value = 0
  runMode.value = form.mode
  lastTarget.value = form.target.trim()
  running.value = true
  controller = new AbortController()
  const client = form.mode === 'client'
  const mbit = Number(form.bitrate)
  try {
    const res = await fetch(apiURL('/agent/iperf'), {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        instance: store.current?.name,
        mode: form.mode,
        interface: form.interface === NONE ? '' : form.interface,
        target: client ? form.target.trim() : '',
        family: form.family === 'auto' ? '' : form.family,
        port: Number(form.port) || 0,
        duration: Number(client ? form.duration : form.listen) || 0,
        protocol: form.protocol,
        streams: Number(form.streams) || 0,
        direction: form.direction,
        bitrate: client && mbit > 0 ? Math.round(mbit * 1e6) : 0,
        one_off: !client && form.oneOff,
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
    listening.value = 0
    controller = null
  }
}
const stop = () => controller?.abort()
onBeforeUnmount(stop)

const canStart = computed(
  () => store.current && auth.canEdit && (form.mode === 'server' || form.target.trim().length > 0),
)

// Bitrates in SI units, as iperf3's bits; transfers in binary units, as
// its bytes.
function rate(bps) {
  if (bps == null) return ''
  const units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s']
  let i = 0
  while (Math.abs(bps) >= 1000 && i < units.length - 1) {
    bps /= 1000
    i++
  }
  return `${bps.toFixed(bps < 10 && i > 0 ? 2 : 1)} ${units[i]}`
}
function size(bytes) {
  if (bytes == null) return ''
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let i = 0
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024
    i++
  }
  return `${bytes.toFixed(i ? 1 : 0)} ${units[i]}`
}
const dirText = (d) => (d === 'sent' ? 'Sent' : 'Received')
// What a sum's sender or receiver alone knows: TCP retransmits, UDP
// jitter and loss.
function extra(s) {
  const parts = []
  if (s.retransmits != null) parts.push(`${s.retransmits} retr`)
  if (s.jitter_ms != null) parts.push(`jitter ${s.jitter_ms.toFixed(3)} ms`)
  if (s.lost_packets != null)
    parts.push(`lost ${s.lost_packets}/${s.packets ?? 0} (${(s.lost_percent ?? 0).toFixed(2)}%)`)
  return parts.join(', ')
}

// The test shown: the one picked in the results, else the latest.
const shown = computed(() => tests.value[(selected.value ?? tests.value.length) - 1] ?? null)

// The results: one row per test and direction, the sender's bitrate next
// to the receiver's.
const results = computed(() =>
  tests.value.flatMap((t) => {
    if (!t.sums) {
      return [{ key: `${t.n}`, test: t, dir: '', state: running.value ? 'running' : 'stopped' }]
    }
    return ['sent', 'received']
      .map((dir) => {
        const of = t.sums.filter((s) => s.dir === dir)
        if (!of.length) return null
        const sender = of.find((s) => !s.receiver)
        const receiver = of.find((s) => s.receiver)
        return {
          key: `${t.n}-${dir}`,
          test: t,
          dir,
          seconds: (receiver ?? sender).end - (receiver ?? sender).start,
          bytes: (receiver ?? sender).bytes,
          sender,
          receiver,
        }
      })
      .filter(Boolean)
  }),
)
const { search: resultQuery, filtered: resultRows } = useSearch(
  results,
  (r) =>
    `${r.test.n} ${r.test.remote} ${r.test.protocol} ${dirText(r.dir)} ${rate(r.sender?.bits_per_second)} ${rate(r.receiver?.bits_per_second)}`,
)

// The shown test's seconds, a row per interval and direction.
const intervals = computed(() =>
  (shown.value?.intervals ?? []).map((s, i) => ({
    key: i,
    time: `${s.start.toFixed(1)}–${s.end.toFixed(1)} s`,
    dir: dirText(s.dir),
    transfer: size(s.bytes),
    bitrate: rate(s.bits_per_second),
    extra: extra(s),
  })),
)
const { search: intervalQuery, filtered: intervalRows } = useSearch(
  intervals,
  (r) => `${r.time} ${r.dir} ${r.transfer} ${r.bitrate} ${r.extra}`,
)

// The graph: each direction's bitrate over the test's time, on a round
// scale above the highest.
const GW = 1000
const GH = 160
function niceMax(v) {
  const p = 10 ** Math.floor(Math.log10(v))
  return [1, 2, 5, 10].map((m) => m * p).find((x) => x >= v)
}
const graph = computed(() => {
  const t = shown.value
  if (!t?.intervals.length) return null
  const span = Math.max(t.duration || 0, ...t.intervals.map((s) => s.end), 1)
  const max = niceMax(Math.max(1, ...t.intervals.map((s) => s.bits_per_second)) * 1.1)
  const line = (dir) => {
    const pts = t.intervals.filter((s) => s.dir === dir)
    if (!pts.length) return null
    return [
      `0,${GH - (pts[0].bits_per_second / max) * GH}`,
      ...pts.map((s) => `${(s.end / span) * GW},${GH - (s.bits_per_second / max) * GH}`),
    ].join(' ')
  }
  return {
    span,
    max,
    ticks: [1, 0.75, 0.5, 0.25, 0].map((f) => f * max),
    sent: line('sent'),
    received: line('received'),
  }
})
</script>

<template>
  <div class="flex flex-col gap-3">
    <form class="card flex flex-wrap items-end gap-3" @submit.prevent="start">
      <UFormField label="Mode">
        <USelect v-model="form.mode" :items="modeItems" class="w-28" :disabled="running" />
      </UFormField>
      <UFormField :label="form.mode === 'server' ? 'Listen on' : 'Source interface'">
        <USelect v-model="form.interface" :items="ifaceItems" class="w-64" :disabled="running" />
      </UFormField>
      <UFormField v-if="form.mode === 'client'" label="Server" class="min-w-64 flex-1">
        <UInput
          v-model="form.target"
          class="w-full font-mono"
          placeholder="192.0.2.1, 2001:db8::1, a named host or a DNS name"
          list="iperf-hosts"
          :disabled="running"
        />
        <datalist id="iperf-hosts">
          <option v-for="n in hostNames" :key="n" :value="n" />
        </datalist>
      </UFormField>
      <UFormField
        label="IP version"
        :title="
          form.mode === 'server'
            ? 'The addresses the server listens on'
            : 'For a named host or DNS name with both an IPv4 and an IPv6 address'
        "
      >
        <USelect v-model="form.family" :items="familyItems" class="w-28" :disabled="running" />
      </UFormField>
      <UFormField label="Port">
        <UInput
          v-model="form.port"
          type="number"
          min="1"
          max="65535"
          class="w-24"
          :disabled="running"
        />
      </UFormField>
      <template v-if="form.mode === 'client'">
        <UFormField label="Protocol">
          <USelect
            v-model="form.protocol"
            :items="protocolItems"
            class="w-24"
            :disabled="running"
          />
        </UFormField>
        <UFormField label="Direction" title="Seen from the firewall">
          <USelect
            v-model="form.direction"
            :items="directionItems"
            class="w-48"
            :disabled="running"
          />
        </UFormField>
        <UFormField label="Streams">
          <UInput
            v-model="form.streams"
            type="number"
            min="1"
            max="128"
            class="w-20"
            :disabled="running"
          />
        </UFormField>
        <UFormField label="Seconds">
          <UInput
            v-model="form.duration"
            type="number"
            min="1"
            max="3600"
            class="w-24"
            :disabled="running"
          />
        </UFormField>
        <UFormField
          label="Bitrate (Mbit/s)"
          title="The target bitrate per stream; empty is unlimited for TCP and 1 Mbit/s for UDP"
        >
          <UInput
            v-model="form.bitrate"
            type="number"
            min="0"
            step="any"
            class="w-28"
            :placeholder="form.protocol === 'udp' ? '1' : 'unlimited'"
            :disabled="running"
          />
        </UFormField>
      </template>
      <template v-else>
        <UFormField label="Listen for (s)" title="The server stops after this time">
          <UInput
            v-model="form.listen"
            type="number"
            min="1"
            max="3600"
            class="w-24"
            :disabled="running"
          />
        </UFormField>
        <UFormField label="One test">
          <div class="flex h-8 items-center">
            <USwitch
              v-model="form.oneOff"
              :disabled="running"
              title="Stop the server after one test"
            />
          </div>
        </UFormField>
      </template>
      <UButton v-if="!running" type="submit" icon="i-lucide-play" :disabled="!canStart"
        >Start</UButton
      >
      <UButton v-else color="error" icon="i-lucide-square" @click="stop">Stop</UButton>
    </form>

    <p v-if="form.mode === 'server' && !running" class="text-sm text-muted">
      The server's port is open in the virtual firewall's input chain (auto rule "iperf3 server")
      while it runs, from any address. It stops when you press Stop, leave this page or the time
      runs out.
    </p>

    <div v-if="running || tests.length" class="flex items-center gap-2 text-sm text-muted">
      <span v-if="running" class="inline-block size-2 animate-pulse rounded-full bg-primary" />
      <template v-if="runMode === 'server'">
        <span v-if="listening"
          >{{ store.current?.name }} listening on port {{ listening }}
          <template v-if="tests.length"> · {{ tests.length }} test(s)</template></span
        >
        <span v-else-if="running">Starting the server…</span>
        <span v-else>Server stopped · {{ tests.length }} test(s)</span>
      </template>
      <template v-else>
        <span
          >{{ store.current?.name }} → {{ lastTarget
          }}<template v-if="shown?.remote && shown.remote !== lastTarget">
            ({{ shown.remote }})</template
          ></span
        >
        <span v-if="running && !shown">Connecting…</span>
      </template>
    </div>

    <div v-if="results.length" class="flex flex-col gap-2">
      <h3 class="font-semibold">Results</h3>
      <SearchInput v-model="resultQuery" />
      <div class="overflow-x-auto rounded border border-default">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-muted">
              <th class="px-2 py-1">Test</th>
              <th class="px-2 py-1">Started</th>
              <th class="px-2 py-1">Remote</th>
              <th class="px-2 py-1">Protocol</th>
              <th class="px-2 py-1">Direction</th>
              <th class="px-2 py-1 text-right">Transfer</th>
              <th class="px-2 py-1 text-right">Sender</th>
              <th class="px-2 py-1 text-right">Receiver</th>
              <th class="px-2 py-1">Details</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="r in resultRows"
              :key="r.key"
              class="cursor-pointer border-t border-default hover:bg-elevated"
              :class="{ 'bg-accented': shown === r.test }"
              title="Show this test's seconds"
              @click="selected = r.test.n"
            >
              <td class="px-2 py-1">{{ r.test.n }}</td>
              <td class="px-2 py-1">{{ r.test.at.toLocaleTimeString() }}</td>
              <td class="px-2 py-1 font-mono">{{ r.test.remote }}</td>
              <td class="px-2 py-1 uppercase">
                {{ r.test.protocol
                }}<span v-if="r.test.streams > 1" class="normal-case"> × {{ r.test.streams }}</span>
              </td>
              <template v-if="r.dir">
                <td class="px-2 py-1">{{ dirText(r.dir) }}</td>
                <td class="px-2 py-1 text-right font-mono">{{ size(r.bytes) }}</td>
                <td class="px-2 py-1 text-right font-mono">
                  {{ rate(r.sender?.bits_per_second) }}
                </td>
                <td class="px-2 py-1 text-right font-mono font-semibold">
                  {{ rate(r.receiver?.bits_per_second) }}
                </td>
                <td class="px-2 py-1">
                  {{
                    [r.sender && extra(r.sender), r.receiver && extra(r.receiver)]
                      .filter(Boolean)
                      .join(', ')
                  }}
                </td>
              </template>
              <td v-else colspan="5" class="px-2 py-1 text-muted">
                {{ r.state === 'running' ? 'Running…' : 'No result (stopped)' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="graph" class="rounded border border-default p-2">
      <div class="mb-1 flex flex-wrap justify-between gap-2 text-xs text-muted">
        <span>
          Test {{ shown.n }}<template v-if="shown.remote"> · {{ shown.remote }}</template>
        </span>
        <span class="flex gap-3">
          <span class="flex items-center gap-1"
            ><span class="inline-block h-0.5 w-4 bg-primary" />sent</span
          >
          <span class="flex items-center gap-1"
            ><span class="inline-block h-0.5 w-4 bg-success" />received</span
          >
          <span>{{ Math.round(graph.span) }} s</span>
        </span>
      </div>
      <div class="flex gap-2">
        <div class="flex flex-col justify-between text-right font-mono text-xs text-muted">
          <span v-for="(t, i) in graph.ticks" :key="i">{{ rate(t) }}</span>
        </div>
        <svg
          class="block flex-1"
          :height="GH"
          :viewBox="`0 0 ${GW} ${GH}`"
          preserveAspectRatio="none"
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
          <polyline
            v-if="graph.sent"
            :points="graph.sent"
            fill="none"
            class="stroke-primary"
            stroke-width="1.5"
            vector-effect="non-scaling-stroke"
          />
          <polyline
            v-if="graph.received"
            :points="graph.received"
            fill="none"
            class="stroke-success"
            stroke-width="1.5"
            vector-effect="non-scaling-stroke"
          />
        </svg>
      </div>
    </div>

    <div v-if="shown" class="flex flex-col gap-2">
      <h3 class="font-semibold">Test {{ shown.n }}, per second</h3>
      <SearchInput v-model="intervalQuery" />
      <div class="overflow-x-auto rounded border border-default">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-muted">
              <th class="px-2 py-1">Interval</th>
              <th class="px-2 py-1">Direction</th>
              <th class="px-2 py-1 text-right">Transfer</th>
              <th class="px-2 py-1 text-right">Bitrate</th>
              <th class="px-2 py-1">Details</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in intervalRows" :key="r.key" class="border-t border-default">
              <td class="px-2 py-1 font-mono">{{ r.time }}</td>
              <td class="px-2 py-1">{{ r.dir }}</td>
              <td class="px-2 py-1 text-right font-mono">{{ r.transfer }}</td>
              <td class="px-2 py-1 text-right font-mono">{{ r.bitrate }}</td>
              <td class="px-2 py-1">{{ r.extra }}</td>
            </tr>
            <tr v-if="!intervalRows.length">
              <td colspan="5" class="py-3 text-center text-muted">
                {{ running ? 'Waiting for the first second…' : 'No intervals.' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
