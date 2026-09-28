<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useLogPanel } from '@/composables/useLogPanel'

// The agent's log and the logged packets at the bottom of the layout. It
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
]

const body = ref(null)
const filter = ref('')

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

// Logged packets are filtered by words, each of which must be part of
// some column ("wan tcp 443", "10.1.2.3", "forward policy").
const packetText = (p) =>
  [
    p.instance,
    p.chain,
    ruleLabel(p),
    p.action,
    p.in_interface,
    p.out_interface,
    p.family,
    p.protocol,
    endpoint(p.src, p.src_port),
    endpoint(p.dst, p.dst_port),
    p.info,
  ]
    .join(' ')
    .toLowerCase()
const packets = computed(() => {
  const words = filter.value.toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return state.packets.lines
  return state.packets.lines.filter((p) => {
    const text = packetText(p)
    return words.every((w) => text.includes(w))
  })
})

// The row that logged: a rule by number, or a locked row (policy,
// invalid, or an auto rule by service).
function ruleLabel(p) {
  if (p.rule) return `rule ${p.rule}`
  return p.builtin === 'auto' ? `auto: ${p.service}` : p.builtin
}

// An address with its port: 192.0.2.1:443, [2001:db8::1]:443.
function endpoint(addr, port) {
  if (!port) return addr
  return addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`
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

function formatTime(iso) {
  const d = new Date(iso)
  const p = (n, w = 2) => String(n).padStart(w, '0')
  return (
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`
  )
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
      <UInput
        v-if="state.tab === 'packets'"
        v-model="filter"
        icon="i-lucide-filter"
        placeholder="Filter: wan tcp 443"
        size="xs"
        class="w-56"
        aria-label="Filter logged packets"
      />
      <span v-if="state.tab === 'packets' && filter" class="text-xs text-muted"
        >{{ packets.length }} of {{ state.packets.lines.length }}</span
      >
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
            <th>Instance</th>
            <th>Chain</th>
            <th>Rule</th>
            <th>Action</th>
            <th>In</th>
            <th>Out</th>
            <th>Proto</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Info</th>
            <th class="text-right">Bytes</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in packets" :key="p.id">
            <td class="text-muted">{{ formatTime(p.time) }}</td>
            <td>{{ p.instance }}</td>
            <td>{{ p.chain }}</td>
            <td>{{ ruleLabel(p) }}</td>
            <td :class="actionClass(p.action)">{{ p.action }}</td>
            <td>{{ p.in_interface }}</td>
            <td>{{ p.out_interface }}</td>
            <td>{{ p.protocol }}</td>
            <td class="break-all">{{ endpoint(p.src, p.src_port) }}</td>
            <td class="break-all">{{ endpoint(p.dst, p.dst_port) }}</td>
            <td class="text-muted">{{ p.info }}</td>
            <td class="text-right">{{ p.length }}</td>
          </tr>
          <tr v-if="!packets.length">
            <td colspan="12" class="text-muted">
              {{
                state.packets.lines.length
                  ? 'No packets match the filter'
                  : 'No packets logged yet. Tick Log on a row of the Rules page and deploy.'
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
      <div v-if="!state.log.lines.length" class="text-muted">No log lines yet</div>
      <div
        v-for="line in state.log.lines"
        :key="line.id"
        class="flex flex-wrap gap-x-2"
        :class="levelClass(line.level)"
      >
        <span class="text-muted">{{ formatTime(line.time) }}</span>
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
