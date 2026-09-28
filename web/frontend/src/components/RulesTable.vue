<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// RulesTable: the firewall rules of one chain as a compact grid edited in
// place. Each change saves its row (`save`); rows reorder by dragging the grip
// (`move`, with indexes into `rows`). Comment rows (kind 'comment') hold one
// text across the row. Right-click a row to insert a rule or comment above or
// below it (`insert(kind, index)`, resolving to a created comment row).
// Address cells take a comma-separated list of addresses, CIDRs, names or
// IP lists (@name); From/To cells a comma-separated list of interfaces and
// interface zones.
import { computed, onMounted, ref } from 'vue'
import { useColumnResize } from '@/composables/useColumnResize'
import { useRowDrag } from '@/composables/useRowDrag'
import { useObjectStore } from '@/stores/objects'
import { bytes } from '@/utils/bytes'

const props = defineProps({
  rows: { type: Array, required: true },
  // input, forward or output: input rules have no To column, output no From.
  chain: { type: String, required: true },
  // Rules the agent adds for configured services and its anti-lockout rule
  // (render.AutoRule), shown read-only above the others.
  auto: { type: Array, default: () => [] },
  // Interface zones and interfaces of the instance ({ value, description }),
  // for suggestions.
  ifaces: { type: Array, required: true },
  // Traffic per rule id since the last deploy (agentapi.RuleCounters), or
  // null when unknown.
  counters: { type: Object, default: null },
  // What the chain dropped by itself since the last deploy
  // (agentapi.ChainDrops; {} when not deployed), or null when unknown.
  drops: { type: Object, default: null },
  // What the chain's built-in rows log: { policy, invalid } (the
  // instance's log_drops and log_invalid hold the chain) and auto, the
  // services of the auto rules that log (log_auto).
  logBuiltin: { type: Object, default: () => ({ policy: false, invalid: false, auto: [] }) },
  // insert(kind, index): add a 'rule' or 'comment' at index of rows.
  insert: { type: Function, required: true },
})
// log-builtin(builtin, service, on): a built-in row's Log box changed;
// builtin is 'policy', 'invalid' or 'auto' (with the auto rule's service).
const emit = defineEmits(['save', 'move', 'edit', 'remove', 'log-builtin'])

const objects = useObjectStore()
onMounted(() => objects.load().catch(() => {}))

const wrap = ref(null)
const { onPointerDown } = useRowDrag({
  wrap,
  label: (i) => {
    const r = props.rows[i]
    if (isComment(r)) return `# ${r.description}`
    return `${ruleNo.value.get(r.id)}. ${r.action} ${r.description || ''}`.trim()
  },
  onMove: (from, to) => emit('move', from, to),
})

const isComment = (r) => r.kind === 'comment'
// ruleNo numbers the rules, leaving out comment rows.
const ruleNo = computed(() => {
  const m = new Map()
  for (const r of props.rows) if (!isComment(r)) m.set(r.id, m.size + 1)
  return m
})

// The context menu acts on the right-clicked row; outside the rules (the
// header, the auto rules, an empty table) it inserts at the top.
let menuIndex = 0
function captureMenuRow(event) {
  const tr = event.target.closest('tbody.user-rules > tr[data-index]')
  menuIndex = tr ? Number(tr.dataset.index) : -1
}
const at = (below) => (menuIndex < 0 ? 0 : menuIndex + (below ? 1 : 0))
async function insertAt(kind, index) {
  const created = await props.insert(kind, index)
  if (created) wrap.value?.querySelector(`[data-comment-id="${created.id}"]`)?.focus()
}
const contextItems = [
  [
    {
      label: 'Add rule above',
      icon: 'i-lucide-arrow-up-to-line',
      onSelect: () => insertAt('rule', at(false)),
    },
    {
      label: 'Add rule below',
      icon: 'i-lucide-arrow-down-to-line',
      onSelect: () => insertAt('rule', at(true)),
    },
  ],
  [
    {
      label: 'Add comment above',
      icon: 'i-lucide-message-square',
      onSelect: () => insertAt('comment', at(false)),
    },
    {
      label: 'Add comment below',
      icon: 'i-lucide-message-square',
      onSelect: () => insertAt('comment', at(true)),
    },
  ],
]

// ifaceTitle lists a cell's interfaces with their descriptions.
const ifaceDesc = computed(() => new Map(props.ifaces.map((it) => [it.value, it.description])))
function ifaceTitle(list, empty) {
  if (!list?.length) return empty
  return list
    .map((n) => (ifaceDesc.value.get(n) ? `${n}: ${ifaceDesc.value.get(n)}` : n))
    .join('\n')
}
// ifaceDescs shows a cell's interface descriptions under its names.
function ifaceDescs(list) {
  return (list ?? [])
    .map((n) => ifaceDesc.value.get(n))
    .filter(Boolean)
    .join(', ')
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
    [...objects.names, ...objects.listRefs].map((n) => ({ value: n })),
    typed.value,
  ),
)

const hasFrom = computed(() => props.chain !== 'output')
const hasTo = computed(() => props.chain !== 'input')
const colCount = computed(() => 13 + hasFrom.value + hasTo.value)
// The columns' default widths (class; none shares the rest). Dragging a
// header's right edge resizes its column, remembered per chain;
// double-clicking it goes back to these.
const columns = computed(() =>
  [
    'w-7',
    'w-14',
    'w-8',
    'w-8',
    hasFrom.value && 'w-36',
    hasTo.value && 'w-36',
    'w-14',
    'w-18',
    'w-24',
    '',
    '',
    'w-18',
    'w-8',
    'w-24',
    '',
  ].filter((c) => c !== false),
)
const table = ref(null)
const resize = useColumnResize({ table, storageKey: () => `rules-grid-widths-${props.chain}` })
const { widths, total: tableWidth } = resize
const onHandle = (fn) => (event) => event.target.classList.contains('col-resize') && fn(event)
const onResizeStart = onHandle(resize.onPointerDown)
const resetWidths = onHandle(resize.reset)
const families = [
  { label: 'any', value: 'any' },
  { label: 'IPv4', value: 'ipv4' },
  { label: 'IPv6', value: 'ipv6' },
]
const protocols = ['any', 'tcp', 'udp', 'icmp', 'icmpv6']
const actions = ['accept', 'drop', 'reject']
const actionClass = { accept: 'text-success', drop: 'text-error', reject: 'text-warning' }
const autoProtocol = (a) => (a.protocol === 'tcp,udp' ? 'tcp+udp' : a.protocol)
const autoPorts = (a) => (a.src_port ? `${a.dst_port} (from ${a.src_port})` : `${a.dst_port}`)
// autoFamily is the IP versions of an auto rule's source addresses.
function autoFamily(a) {
  if (!a.source?.length) return 'any'
  const v6 = a.source.filter((s) => s.includes(':')).length
  if (v6 === 0) return 'IPv4'
  return v6 === a.source.length ? 'IPv6' : 'any'
}
const autoDescription = (a) =>
  a.service === 'anti-lockout' ? 'anti-lockout, from portitor-agent config' : a.service
const autoTitle = (a) =>
  a.service === 'anti-lockout'
    ? 'Added by portitor-agent so allow_from keeps reaching its API; set anti_lockout in agent.yaml to change it'
    : 'Added for a configured service; change the service to change this rule'

// The traffic cell shows In above Out. In is what the rule matched plus the
// rest of the connections it accepted in the same direction, sent by the
// side that opened them; Out the replies. Rules the agent has no counters
// for (not deployed, disabled) show nothing.
const counter = (r) => props.counters?.[r.id]
function counterTitle(r) {
  const c = counter(r)
  if (!c) return props.counters ? 'Not deployed' : 'Agent not reachable'
  const line = (label, dir, what) =>
    `${label}: ${c[`${dir}_bytes`].toLocaleString()} bytes, ${c[`${dir}_packets`].toLocaleString()} packets ${what}`
  return [
    line('In', 'orig', 'from the side that opened the connection'),
    line('Out', 'reply', 'of replies'),
    'since the last deploy',
  ].join('\n')
}

// Drop rows: invalid packets are dropped before the rules, what no rule
// decided on after them (the chain's policy).
function dropTitle(reason) {
  if (!props.drops) return 'Agent not reachable'
  const n = props.drops[`${reason}_packets`]
  if (n === undefined) return 'Not deployed'
  return `${props.drops[`${reason}_bytes`].toLocaleString()} bytes, ${n.toLocaleString()} packets dropped since the last deploy`
}
const dropCount = (reason) => props.drops?.[`${reason}_packets`]

// The built-in rows log rate limited (render.builtinLogLimit).
const builtinLogLimit = 'at most 10 packets a second'

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
// row that has it (comment rows skip rules and the other way round), like a
// spreadsheet; leaving the cell saves it (change event).
function onKeydown(event, index) {
  const step = { Enter: 1, ArrowDown: 1, ArrowUp: -1 }[event.key]
  if (!step || event.isComposing) return
  const col = event.target.dataset.col
  const trs = wrap.value.querySelectorAll('tbody.user-rules > tr')
  let next = null
  for (let i = index + step; !next && i >= 0 && i < trs.length; i += step) {
    next = trs[i].querySelector(`[data-col="${col}"]`)
  }
  event.preventDefault()
  if (next && !next.disabled) next.focus()
  else event.target.blur()
}
</script>

<template>
  <UContextMenu :items="contextItems">
    <div
      ref="wrap"
      class="rules-grid overflow-auto rounded-md ring ring-default"
      @contextmenu.capture="captureMenuRow"
    >
      <table
        ref="table"
        class="table-fixed border-collapse text-xs"
        :class="{ 'w-full min-w-[68rem]': !widths }"
        :style="widths ? { width: `${tableWidth}px` } : undefined"
      >
        <colgroup>
          <col
            v-for="(cls, i) in columns"
            :key="i"
            :class="widths ? undefined : cls || undefined"
            :style="widths ? { width: `${widths[i]}px` } : undefined"
          />
        </colgroup>
        <thead @pointerdown="onResizeStart" @dblclick="resetWidths">
          <tr>
            <th><span class="col-resize" /></th>
            <th><span class="col-resize" /></th>
            <th title="Evaluated top to bottom">#<span class="col-resize" /></th>
            <th title="Enabled">On<span class="col-resize" /></th>
            <th v-if="hasFrom">From<span class="col-resize" /></th>
            <th v-if="hasTo">To<span class="col-resize" /></th>
            <th>IP<span class="col-resize" /></th>
            <th>Protocol<span class="col-resize" /></th>
            <th>Ports<span class="col-resize" /></th>
            <th>Source<span class="col-resize" /></th>
            <th>Destination<span class="col-resize" /></th>
            <th>Action<span class="col-resize" /></th>
            <th title="Log matches">Log<span class="col-resize" /></th>
            <th
              class="text-end"
              title="Bytes since the last deploy. In: sent by the side that opened the connections; out: the replies"
            >
              In / Out<span class="col-resize" />
            </th>
            <th>Description<span class="col-resize" /></th>
          </tr>
        </thead>
        <tbody class="auto-rules">
          <tr
            title="Packets that belong to no known connection, such as a stray TCP packet; dropped before the rules"
          >
            <td class="text-center text-muted">
              <UIcon name="i-lucide-lock" class="size-3.5 align-middle" />
            </td>
            <td class="text-center text-muted">auto</td>
            <td :colspan="colCount - 6">
              <span class="text-muted">invalid: no known connection</span>
            </td>
            <td><span class="font-semibold text-error">drop</span></td>
            <td class="text-center">
              <input
                type="checkbox"
                class="accent-primary"
                :checked="logBuiltin.invalid"
                :title="`Log the invalid packets (${builtinLogLimit}) to the log panel's Logged packets`"
                @change="emit('log-builtin', 'invalid', '', $event.target.checked)"
              />
            </td>
            <td class="counter" :title="dropTitle('invalid')">
              <template v-if="dropCount('invalid') !== undefined">
                <div>{{ bytes(drops.invalid_bytes) }}</div>
                <div>{{ dropCount('invalid').toLocaleString() }} pkt</div>
              </template>
            </td>
            <td><span>invalid packets</span></td>
          </tr>
          <tr v-for="a in auto" :key="a.service" :title="autoTitle(a)">
            <td class="text-center text-muted">
              <UIcon name="i-lucide-lock" class="size-3.5 align-middle" />
            </td>
            <td class="text-center text-muted">auto</td>
            <td />
            <td class="text-center">
              <input type="checkbox" class="accent-primary" checked disabled />
            </td>
            <td v-if="hasFrom" :title="ifaceTitle(a.in_interfaces, 'any')">
              <span :class="{ 'text-muted': !a.in_interfaces?.length }">{{
                a.in_interfaces?.length ? a.in_interfaces.join(', ') : 'any'
              }}</span>
              <div v-if="ifaceDescs(a.in_interfaces)" class="iface-desc">
                {{ ifaceDescs(a.in_interfaces) }}
              </div>
            </td>
            <td v-if="hasTo"><span class="text-muted">any</span></td>
            <td>
              <span>{{ autoFamily(a) }}</span>
            </td>
            <td>
              <span>{{ autoProtocol(a) }}</span>
            </td>
            <td>
              <span class="font-mono">{{ autoPorts(a) }}</span>
            </td>
            <td :title="a.source?.join(', ')">
              <span v-if="a.source?.length" class="font-mono">{{ a.source.join(', ') }}</span>
              <span v-else class="text-muted">any</span>
            </td>
            <td><span class="text-muted">any</span></td>
            <td><span class="font-semibold text-success">accept</span></td>
            <td class="text-center">
              <input
                type="checkbox"
                class="accent-primary"
                :checked="logBuiltin.auto?.includes(a.service)"
                :title="`Log what this rule accepts (${builtinLogLimit}) to the log panel's Logged packets`"
                @change="emit('log-builtin', 'auto', a.service, $event.target.checked)"
              />
            </td>
            <td />
            <td>
              <span>{{ autoDescription(a) }}</span>
            </td>
          </tr>
        </tbody>
        <tbody class="user-rules">
          <template v-for="(r, i) in rows" :key="r.id">
            <tr v-if="isComment(r)" class="rule-comment" :data-index="i">
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
                <div class="flex justify-end">
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
              <td :colspan="colCount - 2">
                <input
                  :value="r.description"
                  data-col="comment"
                  :data-comment-id="r.id"
                  placeholder="Comment"
                  :title="r.description"
                  @change="setText(r, 'description', $event)"
                  @keydown="onKeydown($event, i)"
                />
              </td>
            </tr>
            <tr v-else :class="{ 'rule-off': !r.enabled }" :data-index="i">
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
              <td class="text-center text-muted tabular-nums">{{ ruleNo.get(r.id) }}</td>
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
                <div v-if="ifaceDescs(r.in_interfaces)" class="iface-desc">
                  {{ ifaceDescs(r.in_interfaces) }}
                </div>
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
                <div v-if="ifaceDescs(r.out_interfaces)" class="iface-desc">
                  {{ ifaceDescs(r.out_interfaces) }}
                </div>
              </td>
              <td>
                <select
                  :value="r.family"
                  data-col="family"
                  @change="set(r, 'family', $event.target.value)"
                >
                  <option v-for="f in families" :key="f.value" :value="f.value">
                    {{ f.label }}
                  </option>
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
              <td class="counter" :title="counterTitle(r)">
                <template v-if="counter(r)">
                  <div><span class="dir">in</span>{{ bytes(counter(r).orig_bytes) }}</div>
                  <div><span class="dir">out</span>{{ bytes(counter(r).reply_bytes) }}</div>
                </template>
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
          </template>
          <tr v-if="!rows.length">
            <td :colspan="colCount" class="py-6 text-center text-muted">Nothing here yet.</td>
          </tr>
        </tbody>
        <tbody class="auto-rules chain-policy">
          <tr title="Traffic no rule accepted, dropped by the chain's policy">
            <td class="text-center text-muted">
              <UIcon name="i-lucide-lock" class="size-3.5 align-middle" />
            </td>
            <td class="text-center text-muted">policy</td>
            <td :colspan="colCount - 6">
              <span class="text-muted">no rule matched</span>
            </td>
            <td><span class="font-semibold text-error">drop</span></td>
            <td class="text-center">
              <input
                type="checkbox"
                class="accent-primary"
                :checked="logBuiltin.policy"
                :title="`Log what no rule matched (${builtinLogLimit}) to the log panel's Logged packets`"
                @change="emit('log-builtin', 'policy', '', $event.target.checked)"
              />
            </td>
            <td class="counter" :title="dropTitle('policy')">
              <template v-if="dropCount('policy') !== undefined">
                <div>{{ bytes(drops.policy_bytes) }}</div>
                <div>{{ dropCount('policy').toLocaleString() }} pkt</div>
              </template>
            </td>
            <td><span>default drop</span></td>
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
  </UContextMenu>
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
.rules-grid th .col-resize {
  position: absolute;
  inset-block: 0;
  inset-inline-end: 0;
  width: 0.375rem;
  cursor: col-resize;
  touch-action: none;
}
.rules-grid th .col-resize:hover {
  background: var(--ui-primary);
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
.rules-grid tbody.auto-rules td {
  background: color-mix(in oklab, var(--ui-bg-elevated) 50%, transparent);
  border-block-end: 1px solid var(--ui-border-accented);
}
.rules-grid tbody.auto-rules tr:last-child td {
  border-block-end: 2px solid var(--ui-border-accented);
}
.rules-grid tbody.auto-rules td > span {
  display: block;
  padding-inline: 0.375rem;
  line-height: 1.75rem;
  overflow: hidden;
  text-overflow: ellipsis;
}
.rules-grid tbody.chain-policy tr:last-child td {
  border-block-start: 2px solid var(--ui-border-accented);
  border-block-end: 0;
}
.rules-grid .iface-desc {
  padding-inline: 0.375rem;
  padding-block-end: 0.125rem;
  margin-block-start: -0.25rem;
  font-size: 0.75rem;
  line-height: 1rem;
  color: var(--ui-text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
}
.rules-grid td.counter {
  padding-inline: 0.375rem;
  font-size: 0.6875rem;
  line-height: 0.875rem;
  text-align: end;
  font-variant-numeric: tabular-nums;
  color: var(--ui-text-muted);
}
.rules-grid td.counter .dir {
  float: inline-start;
  opacity: 0.7;
}
.rules-grid tr.rule-comment td {
  background: color-mix(in oklab, var(--ui-bg-elevated) 40%, transparent);
}
.rules-grid tr.rule-comment input {
  font-style: italic;
  color: var(--ui-text-muted);
}
.rules-grid tr.rule-off > td:not(.keep) {
  opacity: 0.45;
}
</style>
