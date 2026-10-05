<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import SearchInput from '@/components/SearchInput.vue'
import { interfaces } from '@/api'
import { useLogPanel } from '@/composables/useLogPanel'
import { withLabel } from '@/composables/useInstanceRefs'
import { useInstanceStore } from '@/stores/instances'
import { logTime } from '@/utils/time'

// The agent's log, the logged packets and DNS queries at the bottom of the layout. It
// takes its height out of the page (a flex item, not an overlay), so
// nothing ends up behind it.
const { state, close, clear, togglePause, setHeight, start, stop } = useLogPanel()

const tabs = [
  { value: 'log', label: 'Agent log', icon: 'i-lucide-terminal' },
  {
    value: 'packets',
    label: 'Logged packets',
    icon: 'i-lucide-list-filter',
    title: 'Packets of the rules with Log ticked on the Rules page, the locked rows included',
  },
  {
    value: 'dns',
    label: 'DNS queries',
    icon: 'i-lucide-globe',
    title: 'Queries to the DNS servers with Query logging on (DNS → DNS server)',
  },
]

const body = ref(null)
// A filter per tab that has one.
const filters = ref({ log: '', packets: '', dns: '' })
const filter = computed({
  get: () => filters.value[state.tab] ?? '',
  set: (v) => (filters.value[state.tab] = v),
})
const placeholders = {
  log: 'Filter: warn instance=office',
  packets: 'Filter: wan tcp 443',
  dns: 'Filter: 192.168.1.10 AAAA',
}

// Follow the tail unless paused. Watching the newest id (not the length)
// keeps following once the buffer is full; the filter and the tab change
// what is shown, so they scroll too.
watch(
  () => [state.tab, state[state.tab].lines.at(-1)?.id, filter.value],
  () => {
    if (!state.paused && body.value) body.value.scrollTop = body.value.scrollHeight
  },
  { flush: 'post' },
)

// Interface labels by instance and name, so a packet shows "WAN (ens18)".
// Loaded when the Logged packets tab is shown.
const instStore = useInstanceStore()
const ifaceLabels = ref(new Map())
async function loadIfaces() {
  try {
    const list = await interfaces.list()
    ifaceLabels.value = new Map(
      list
        .filter((i) => i.label)
        .map((i) => [`${instStore.nameOf(i.instance_id)}/${i.name}`, i.label]),
    )
  } catch {
    // Bare names are fine.
  }
}
watch(
  () => state.tab === 'packets',
  (on) => on && loadIfaces(),
  { immediate: true },
)
const ifaceText = (p, name) => withLabel(ifaceLabels.value.get(`${p.instance}/${name}`), name)

// Logged packets are filtered by words, each of which must be part of
// some column ("wan tcp 443", "10.1.2.3", "forward policy").
const packetText = (p) =>
  [
    p.instance,
    p.chain,
    ruleLabel(p),
    p.action,
    ifaceText(p, p.in_interface),
    ifaceText(p, p.out_interface),
    p.family,
    p.protocol,
    p.src,
    p.src_port,
    p.dst,
    p.dst_port,
    p.dst_service,
    p.info,
  ]
    .join(' ')
    .toLowerCase()
// The lines whose text holds every word of the tab's filter.
function filtered(lines, text, f) {
  const words = f.toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return lines
  return lines.filter((l) => {
    const t = text(l)
    return words.every((w) => t.includes(w))
  })
}
// Every tab shows the selected VF's lines only; the default VF (the
// host) shows them all. An agent log line names its VF in its attrs, if any.
const vfName = computed(() =>
  instStore.current?.is_default ? '' : (instStore.current?.name ?? ''),
)
const ofVF = (lines, inst) => (vfName.value ? lines.filter((l) => inst(l) === vfName.value) : lines)
// The GUI's own messages (source=gui) show on every VF.
const logLines = computed(() =>
  ofVF(state.log.lines, (l) => (l.attrs?.source === 'gui' ? vfName.value : l.attrs?.instance)),
)
// Agent log lines by level, message and attrs ("error wg0", "instance=office").
const logText = (l) =>
  [l.level, l.message, ...attrs(l).map(([k, v]) => `${k}=${v}`)].join(' ').toLowerCase()
const logShown = computed(() => filtered(logLines.value, logText, filters.value.log))
const packetLines = computed(() => ofVF(state.packets.lines, (p) => p.instance))
const dnsLines = computed(() => ofVF(state.dns.lines, (q) => q.instance))

const packets = computed(() => filtered(packetLines.value, packetText, filters.value.packets))

const queryText = (q) =>
  [q.instance, q.client, q.name, q.class, q.type, q.flags, q.server].join(' ').toLowerCase()
const queries = computed(() => filtered(dnsLines.value, queryText, filters.value.dns))
const shown = computed(
  () => ({ log: logShown.value, packets: packets.value, dns: queries.value })[state.tab],
)
const total = computed(
  () =>
    ({ log: logLines.value, packets: packetLines.value, dns: dnsLines.value })[state.tab].length,
)

// The row that logged: a rule by number, or a locked row (policy,
// invalid, or an auto rule by service).
function ruleLabel(p) {
  if (p.rule) return `rule ${p.rule}`
  return p.builtin === 'auto' ? `auto: ${p.service}` : p.builtin
}

// A destination port with its name from the agent's /etc/services:
// "443 (https)".
function dstPort(p) {
  if (!p.dst_port) return ''
  return p.dst_service ? `${p.dst_port} (${p.dst_service})` : String(p.dst_port)
}

const actionClasses = { accept: 'text-success', drop: 'text-error', reject: 'text-warning' }
const actionClass = (action) => actionClasses[action]

function startResize(event) {
  event.preventDefault()
  const startY = event.clientY
  const startHeight = state.height
  const onMove = (e) => setHeight(startHeight + (startY - e.clientY))
  const onUp = () => {
    window.removeEventListener('mousemove', onMove)
    window.removeEventListener('mouseup', onUp)
    setHeight(state.height, true)
  }
  window.addEventListener('mousemove', onMove)
  window.addEventListener('mouseup', onUp)
}

function levelClass(level) {
  if (level === 'ERROR') return 'text-error'
  if (level === 'WARN') return 'text-warning'
  if (level === 'DEBUG') return 'text-muted'
  return ''
}

function attrs(line) {
  return Object.entries(line.attrs ?? {}).filter(([, v]) => v !== '')
}

onMounted(() => {
  setHeight(state.height)
  start()
})
onUnmounted(stop)
</script>

<template>
  <section
    class="flex w-full shrink-0 flex-col overflow-hidden border-t border-default bg-default"
    :style="{ height: state.height + 'px' }"
  >
    <div class="h-1 shrink-0 cursor-row-resize hover:bg-primary/30" @mousedown="startResize"></div>
    <div class="flex shrink-0 items-center gap-2 border-b border-default px-3 py-1.5">
      <div class="flex items-center gap-1" role="tablist">
        <UButton
          v-for="t in tabs"
          :key="t.value"
          role="tab"
          :aria-selected="state.tab === t.value"
          :icon="t.icon"
          :label="t.label"
          :title="t.title"
          :variant="state.tab === t.value ? 'soft' : 'ghost'"
          :color="state.tab === t.value ? 'primary' : 'neutral'"
          size="xs"
          @click="state.tab = t.value"
        />
      </div>
      <SearchInput v-model="filter" :placeholder="placeholders[state.tab]" size="xs" class="w-56" />
      <span v-if="filter" class="text-xs text-muted">{{ shown.length }} of {{ total }}</span>
      <UTooltip v-if="state.error" :text="state.error">
        <UBadge color="error" variant="subtle" size="sm" label="agent unreachable" />
      </UTooltip>
      <UBadge v-if="state.paused" color="neutral" variant="subtle" size="sm" label="paused" />
      <div class="ml-auto flex items-center gap-1">
        <UButton
          :icon="state.paused ? 'i-lucide-play' : 'i-lucide-pause'"
          variant="ghost"
          color="neutral"
          size="xs"
          :title="state.paused ? 'Follow new lines' : 'Stop following new lines'"
          @click="togglePause"
        />
        <UButton
          icon="i-lucide-trash-2"
          variant="ghost"
          color="neutral"
          size="xs"
          title="Clear"
          @click="clear"
        />
        <UButton
          icon="i-lucide-x"
          variant="ghost"
          color="neutral"
          size="xs"
          title="Close"
          @click="close"
        />
      </div>
    </div>
    <div
      v-if="state.tab === 'packets'"
      ref="body"
      class="min-h-0 flex-1 overflow-auto font-mono text-xs [overflow-anchor:none]"
    >
      <table class="packet-log w-full">
        <thead>
          <tr>
            <th>Time</th>
            <th>VF</th>
            <th>Chain</th>
            <th>Rule</th>
            <th>Action</th>
            <th>In</th>
            <th>Out</th>
            <th>Proto</th>
            <th>Source</th>
            <th class="text-right">Port</th>
            <th>Destination</th>
            <th>Port</th>
            <th>Info</th>
            <th class="text-right">Bytes</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in packets" :key="p.id">
            <td class="text-muted">{{ logTime(p.time) }}</td>
            <td>{{ p.instance }}</td>
            <td>{{ p.chain }}</td>
            <td>{{ ruleLabel(p) }}</td>
            <td :class="actionClass(p.action)">{{ p.action }}</td>
            <td>{{ ifaceText(p, p.in_interface) }}</td>
            <td>{{ ifaceText(p, p.out_interface) }}</td>
            <td>{{ p.protocol }}</td>
            <td class="break-all">{{ p.src }}</td>
            <td class="text-right">{{ p.src_port || '' }}</td>
            <td class="break-all">{{ p.dst }}</td>
            <td class="whitespace-nowrap">{{ dstPort(p) }}</td>
            <td class="text-muted">{{ p.info }}</td>
            <td class="text-right">{{ p.length }}</td>
          </tr>
          <tr v-if="!packets.length">
            <td colspan="14" class="text-muted">
              {{
                packetLines.length
                  ? 'No packets match the filter'
                  : 'No packets logged yet. Tick Log on a row of the Rules page and deploy.'
              }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div
      v-else-if="state.tab === 'dns'"
      ref="body"
      class="min-h-0 flex-1 overflow-auto font-mono text-xs [overflow-anchor:none]"
    >
      <table class="packet-log w-full">
        <thead>
          <tr>
            <th>Time</th>
            <th>VF</th>
            <th>Client</th>
            <th class="text-right">Port</th>
            <th>Name</th>
            <th>Class</th>
            <th>Type</th>
            <th title="+ recursion desired, E(n) EDNS, T TCP, D DO, C CD, S signed, K/V cookie">
              Flags
            </th>
            <th>Server</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="q in queries" :key="q.id">
            <td class="text-muted">{{ logTime(q.time) }}</td>
            <td>{{ q.instance }}</td>
            <td class="break-all">{{ q.client }}</td>
            <td class="text-right">{{ q.client_port || '' }}</td>
            <td class="break-all">{{ q.name }}</td>
            <td>{{ q.class }}</td>
            <td>{{ q.type }}</td>
            <td class="text-muted">{{ q.flags }}</td>
            <td class="break-all">{{ q.server }}</td>
          </tr>
          <tr v-if="!queries.length">
            <td colspan="9" class="text-muted">
              {{
                dnsLines.length
                  ? 'No queries match the filter'
                  : 'No DNS queries logged yet. Turn on Query logging under DNS → DNS server and deploy.'
              }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div
      v-else
      ref="body"
      class="min-h-0 flex-1 overflow-auto px-3 py-2 font-mono text-xs [overflow-anchor:none]"
    >
      <div v-if="!logShown.length" class="text-muted">
        {{ logLines.length ? 'No log lines match the filter' : 'No log lines yet' }}
      </div>
      <div
        v-for="line in logShown"
        :key="line.id"
        class="flex flex-wrap gap-x-2"
        :class="levelClass(line.level)"
      >
        <span class="text-muted">{{ logTime(line.time) }}</span>
        <span class="w-11 shrink-0 font-semibold">{{ line.level }}</span>
        <span class="break-all">{{ line.message }}</span>
        <span v-for="[k, v] in attrs(line)" :key="k" class="break-all text-muted"
          >{{ k }}={{ v }}</span
        >
      </div>
    </div>
  </section>
</template>

<style scoped>
.packet-log th {
  position: sticky;
  top: 0;
  background: var(--ui-bg);
  border-block-end: 1px solid var(--ui-border);
  font-weight: 600;
  text-align: left;
  white-space: nowrap;
}
.packet-log th,
.packet-log td {
  padding: 0.125rem 0.75rem 0.125rem 0;
  vertical-align: top;
}
.packet-log th:first-child,
.packet-log td:first-child {
  padding-inline-start: 0.75rem;
  white-space: nowrap;
}
</style>
