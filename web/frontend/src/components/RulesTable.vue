<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// RulesTable: the firewall rules of one chain as a compact grid edited in
// place. Each change saves its row (`save`); rows reorder by dragging the grip
// (`move`, with indexes into `rows`).
// Address cells take a comma-separated list of addresses, CIDRs or names;
// From/To cells a comma-separated list of interfaces and interface zones.
import { computed, onMounted, ref } from 'vue'
import { useRowDrag } from '@/composables/useRowDrag'
import { useObjectStore } from '@/stores/objects'

const props = defineProps({
  rows: { type: Array, required: true },
  // input, forward or output: input rules have no To column, output no From.
  chain: { type: String, required: true },
  // Interface zones and interfaces of the instance ({ value, description }),
  // for suggestions.
  ifaces: { type: Array, required: true },
})
const emit = defineEmits(['save', 'move', 'edit', 'remove'])

const objects = useObjectStore()
onMounted(() => objects.load().catch(() => {}))

const wrap = ref(null)
const { onPointerDown } = useRowDrag({
  wrap,
  label: (i) => {
    const r = props.rows[i]
    return `${i + 1}. ${r.action} ${r.description || ''}`.trim()
  },
  onMove: (from, to) => emit('move', from, to),
})

// ifaceTitle lists a cell's interfaces with their descriptions.
const ifaceDesc = computed(() => new Map(props.ifaces.map((it) => [it.value, it.description])))
function ifaceTitle(list, empty) {
  if (!list?.length) return empty
  return list
    .map((n) => (ifaceDesc.value.get(n) ? `${n}: ${ifaceDesc.value.get(n)}` : n))
    .join('\n')
}

// A datalist only offers options that start with the input's text, so the
// suggestions for a list cell are built from the focused cell's text: the
// entries before the last one plus each name (completing the last entry),
// and, once the last entry is a whole name or followed by a comma, the whole
// text plus each name not yet in the list.
const typed = ref('')
function onFocus(event) {
  typed.value = event.target.value
}
function listSuggestions(names, text) {
  const parts = text.split(/[\s,]+/)
  const last = parts.pop()
  const head = parts.filter((s) => s)
  const used = new Set(head)
  const join = (list) => (list.length ? list.join(', ') + ', ' : '')
  const out = []
  for (const it of names) {
    if (!used.has(it.value)) out.push({ ...it, value: join(head) + it.value })
  }
  if (last && names.some((it) => it.value === last)) {
    used.add(last)
    for (const it of names) {
      if (!used.has(it.value)) out.push({ ...it, value: join([...head, last]) + it.value })
    }
  }
  return out
}
const ifaceSuggestions = computed(() => listSuggestions(props.ifaces, typed.value))
const nameSuggestions = computed(() =>
  listSuggestions(
    objects.names.map((n) => ({ value: n })),
    typed.value,
  ),
)

const hasFrom = computed(() => props.chain !== 'output')
const hasTo = computed(() => props.chain !== 'input')
const colCount = computed(() => 12 + hasFrom.value + hasTo.value)
const families = [
  { label: 'any', value: 'any' },
  { label: 'IPv4', value: 'ipv4' },
  { label: 'IPv6', value: 'ipv6' },
]
const protocols = ['any', 'tcp', 'udp', 'icmp', 'icmpv6']
const actions = ['accept', 'drop', 'reject']
const actionClass = { accept: 'text-success', drop: 'text-error', reject: 'text-warning' }
const hasPorts = (r) => r.protocol === 'tcp' || r.protocol === 'udp'

function set(r, key, value) {
  r[key] = value
  if (key === 'protocol' && !hasPorts(r)) r.dst_ports = ''
  emit('save', r)
}

function setText(r, key, event) {
  set(r, key, event.target.value.trim())
}

// setList saves a comma-separated cell as a list.
function setList(r, key, event) {
  set(
    r,
    key,
    event.target.value.split(/[\s,]+/).filter((s) => s),
  )
}

// Enter and the up/down arrows move to the same column in the next/previous
// row, like a spreadsheet; leaving the cell saves it (change event).
function onKeydown(event, index) {
  const step = { Enter: 1, ArrowDown: 1, ArrowUp: -1 }[event.key]
  if (!step || event.isComposing) return
  const col = event.target.dataset.col
  const next = wrap.value.querySelector(
    `tbody > tr:nth-child(${index + 1 + step}) [data-col="${col}"]`,
  )
  event.preventDefault()
  if (next && !next.disabled) next.focus()
  else event.target.blur()
}
</script>

<template>
  <div ref="wrap" class="rules-grid overflow-auto rounded-md ring ring-default">
    <table class="w-full min-w-[64rem] table-fixed border-collapse text-xs">
      <colgroup>
        <col class="w-7" />
        <col class="w-14" />
        <col class="w-8" />
        <col class="w-8" />
        <col v-if="hasFrom" class="w-28" />
        <col v-if="hasTo" class="w-28" />
        <col class="w-14" />
        <col class="w-18" />
        <col class="w-24" />
        <col />
        <col />
        <col class="w-18" />
        <col class="w-8" />
        <col />
      </colgroup>
      <thead>
        <tr>
          <th />
          <th />
          <th title="Evaluated top to bottom">#</th>
          <th title="Enabled">On</th>
          <th v-if="hasFrom">From</th>
          <th v-if="hasTo">To</th>
          <th>IP</th>
          <th>Protocol</th>
          <th>Ports</th>
          <th>Source</th>
          <th>Destination</th>
          <th>Action</th>
          <th title="Log matches">Log</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(r, i) in rows" :key="r.id" :class="{ 'rule-off': !r.enabled }">
          <td class="keep">
            <span
              class="flex h-7 cursor-grab touch-none items-center justify-center text-muted select-none active:cursor-grabbing"
              title="Drag to reorder"
              @pointerdown="onPointerDown(i, $event)"
            >
              <UIcon name="i-lucide-grip-vertical" class="pointer-events-none size-3.5" />
            </span>
          </td>
          <td class="keep">
            <div class="flex justify-center">
              <UButton
                size="xs"
                color="neutral"
                variant="ghost"
                icon="i-lucide-pencil"
                title="Details"
                @click="emit('edit', r)"
              />
              <UButton
                size="xs"
                color="error"
                variant="ghost"
                icon="i-lucide-trash"
                title="Delete"
                @click="emit('remove', r)"
              />
            </div>
          </td>
          <td class="text-center text-muted tabular-nums">{{ i + 1 }}</td>
          <td class="keep text-center">
            <input
              type="checkbox"
              class="accent-primary"
              :checked="r.enabled"
              title="Enabled"
              @change="set(r, 'enabled', $event.target.checked)"
            />
          </td>
          <td v-if="hasFrom">
            <input
              :value="(r.in_interfaces ?? []).join(', ')"
              data-col="in_interfaces"
              :list="`rules-grid-ifaces-${chain}`"
              placeholder="any"
              :title="ifaceTitle(r.in_interfaces, 'Incoming interfaces or interface zones')"
              @focus="onFocus"
              @input="onFocus"
              @change="setList(r, 'in_interfaces', $event)"
              @keydown="onKeydown($event, i)"
            />
          </td>
          <td v-if="hasTo">
            <input
              :value="(r.out_interfaces ?? []).join(', ')"
              data-col="out_interfaces"
              :list="`rules-grid-ifaces-${chain}`"
              placeholder="any"
              :title="ifaceTitle(r.out_interfaces, 'Outgoing interfaces or interface zones')"
              @focus="onFocus"
              @input="onFocus"
              @change="setList(r, 'out_interfaces', $event)"
              @keydown="onKeydown($event, i)"
            />
          </td>
          <td>
            <select
              :value="r.family"
              data-col="family"
              @change="set(r, 'family', $event.target.value)"
            >
              <option v-for="f in families" :key="f.value" :value="f.value">{{ f.label }}</option>
            </select>
          </td>
          <td>
            <select
              :value="r.protocol"
              data-col="protocol"
              @change="set(r, 'protocol', $event.target.value)"
            >
              <option v-for="p in protocols" :key="p" :value="p">{{ p }}</option>
            </select>
          </td>
          <td>
            <input
              :value="r.dst_ports"
              data-col="dst_ports"
              class="font-mono"
              :disabled="!hasPorts(r)"
              :placeholder="hasPorts(r) ? 'any' : ''"
              @change="setText(r, 'dst_ports', $event)"
              @keydown="onKeydown($event, i)"
            />
          </td>
          <td>
            <input
              :value="(r.src_addrs ?? []).join(', ')"
              data-col="src_addrs"
              class="font-mono"
              :list="`rules-grid-names-${chain}`"
              placeholder="any"
              :title="(r.src_addrs ?? []).join(', ')"
              @focus="onFocus"
              @input="onFocus"
              @change="setList(r, 'src_addrs', $event)"
              @keydown="onKeydown($event, i)"
            />
          </td>
          <td>
            <input
              :value="(r.dst_addrs ?? []).join(', ')"
              data-col="dst_addrs"
              class="font-mono"
              :list="`rules-grid-names-${chain}`"
              placeholder="any"
              :title="(r.dst_addrs ?? []).join(', ')"
              @focus="onFocus"
              @input="onFocus"
              @change="setList(r, 'dst_addrs', $event)"
              @keydown="onKeydown($event, i)"
            />
          </td>
          <td>
            <select
              :value="r.action"
              data-col="action"
              class="font-semibold"
              :class="actionClass[r.action]"
              @change="set(r, 'action', $event.target.value)"
            >
              <option v-for="a in actions" :key="a" :value="a">{{ a }}</option>
            </select>
          </td>
          <td class="text-center">
            <input
              type="checkbox"
              class="accent-primary"
              :checked="r.log"
              title="Log matches"
              @change="set(r, 'log', $event.target.checked)"
            />
          </td>
          <td>
            <input
              :value="r.description"
              data-col="description"
              :title="r.description"
              @change="setText(r, 'description', $event)"
              @keydown="onKeydown($event, i)"
            />
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td :colspan="colCount" class="py-6 text-center text-muted">Nothing here yet.</td>
        </tr>
      </tbody>
    </table>
    <datalist :id="`rules-grid-names-${chain}`">
      <option v-for="it in nameSuggestions" :key="it.value" :value="it.value" />
    </datalist>
    <datalist :id="`rules-grid-ifaces-${chain}`">
      <option
        v-for="it in ifaceSuggestions"
        :key="it.value"
        :value="it.value"
        :label="it.description || undefined"
      />
    </datalist>
  </div>
</template>

<style>
.rules-grid {
  max-height: max(24rem, calc(100dvh - 14rem));
  overscroll-behavior: contain;
}
.rules-grid th {
  position: sticky;
  top: 0;
  z-index: 10;
  padding: 0.25rem 0.375rem;
  text-align: start;
  font-weight: 500;
  background: var(--ui-bg-elevated);
  border-block-end: 1px solid var(--ui-border-accented);
}
.rules-grid th,
.rules-grid td {
  border-inline-end: 1px solid var(--ui-border-accented);
  white-space: nowrap;
  overflow: hidden;
}
.rules-grid th:last-child,
.rules-grid td:last-child {
  border-inline-end: 0;
}
.rules-grid td {
  padding: 0;
  height: 1.75rem;
}
.rules-grid tbody tr:not(:last-child) td {
  border-block-end: 1px solid var(--ui-border-accented);
}
.rules-grid tbody tr:hover td {
  background: color-mix(in oklab, var(--ui-bg-elevated) 70%, transparent);
}
.rules-grid td:focus-within {
  position: relative;
  z-index: 1;
  background: var(--ui-bg);
  box-shadow: inset 0 0 0 2px var(--ui-primary);
}
.rules-grid td > select,
.rules-grid td > input:not([type='checkbox']) {
  display: block;
  width: 100%;
  height: 1.75rem;
  padding-inline: 0.375rem;
  background: transparent;
  outline: none;
  text-overflow: ellipsis;
}
.rules-grid td > select {
  cursor: pointer;
}
.rules-grid td > input:disabled {
  cursor: not-allowed;
  background: color-mix(in oklab, var(--ui-bg-elevated) 60%, transparent);
}
.rules-grid option {
  background: var(--ui-bg);
  color: var(--ui-text);
}
.rules-grid tr.rule-off > td:not(.keep) {
  opacity: 0.45;
}
</style>
