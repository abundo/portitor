<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// RulesTable: the firewall rules of one chain as a compact grid edited in
// place. Each change saves its row (`save`); rows reorder by dragging the grip
// (`move`, with indexes into `rows`). Comment rows (kind 'comment') hold one
// text across the row; a click on a rule's grip opens its details (`edit`).
// Group rows (kind 'group') head a section: the rows below them up to the
// next group, which their chevron folds away (remembered per browser).
// Right-click a row to insert a rule, comment or group above or below it
// (`insert(kind, index)`, resolving to a created comment or group row) or to
// delete it (`remove`); a rule can also be copied, the copy placed below it
// and disabled (`copy(rule, index)`, resolving to the created row).
// Address cells take a comma-separated list of addresses, CIDRs, names or
// IP lists (@name); From/To cells a comma-separated list of interfaces and
// interface zones, ticked in a menu; the Service cell a menu to tick services in (custom and
// predefined, such as ssh or ping), whose search can create a new one.
// Each of these offers "any" first, which empties the cell.
// The search box above the grid shows only the rows with a cell containing
// its text, with the groups they are in open, and highlights the matches.
import { computed, onMounted, ref } from 'vue'
import { useColumnResize } from '@/composables/useColumnResize'
import { useServiceDialog } from '@/composables/useServiceDialog'
import { useRowDrag } from '@/composables/useRowDrag'
import { useObjectStore } from '@/stores/objects'
import { bytes } from '@/utils/bytes'
import { autoDescription, autoService, serviceMatches } from '@/utils/services'

const props = defineProps({
  rows: { type: Array, required: true },
  // input, forward or output: input rules have no To column, output no From.
  chain: { type: String, required: true },
  // Rules the agent adds for configured services and its anti-lockout rule
  // (render.AutoRule), shown read-only above the others.
  auto: { type: Array, default: () => [] },
  // Interface zones and interfaces of the instance ({ label, value,
  // description }; label is "WAN (ens18)" for a labelled interface), for
  // suggestions and the label line under a cell.
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
  // insert(kind, index): add a 'rule', 'comment' or 'group' at index of rows.
  insert: { type: Function, required: true },
  // copy(rule, index): add a disabled copy of rule at index of rows.
  copy: { type: Function, required: true },
  // readOnly shows the rules without letting them change (a viewer).
  readOnly: { type: Boolean, default: false },
})
// log-builtin(builtin, service, on): a built-in row's Log box changed;
// builtin is 'policy', 'invalid' or 'auto' (with the auto rule's service).
// view(row): a locked row was clicked, to show it read-only: an auto rule,
// or { builtin } for 'invalid', 'dnat' (port forwards) or 'policy'.
const emit = defineEmits(['save', 'move', 'edit', 'view', 'remove', 'log-builtin'])

const objects = useObjectStore()
onMounted(() => objects.load().catch(() => {}))

const wrap = ref(null)
const { onPointerDown } = useRowDrag({
  wrap,
  rowSelector: 'tbody.user-rules > tr[data-index]',
  label: (i) => {
    const r = props.rows[i]
    if (isComment(r)) return `# ${r.description}`
    if (isGroup(r)) return `§ ${r.description}`
    return `${ruleNo.value.get(r.id)}. ${r.action} ${r.description || ''}`.trim()
  },
  onMove,
  onClick: (i) => isNote(props.rows[i]) || emit('edit', props.rows[i]),
})

const isComment = (r) => r.kind === 'comment'
const isGroup = (r) => r.kind === 'group'
const isNote = (r) => isComment(r) || isGroup(r)
// ruleNo numbers the rules, leaving out comment and group rows.
const ruleNo = computed(() => {
  const m = new Map()
  for (const r of props.rows) if (!isNote(r)) m.set(r.id, m.size + 1)
  return m
})

// Folded groups by id, kept in the browser (group ids are never reused).
const collapsedKey = 'rules-collapsed-groups'
const collapsed = ref(new Set())
try {
  collapsed.value = new Set(JSON.parse(localStorage.getItem(collapsedKey)) ?? [])
} catch {
  // No storage: every group starts open.
}
function setCollapsed(ids) {
  collapsed.value = new Set(ids)
  try {
    localStorage.setItem(collapsedKey, JSON.stringify([...collapsed.value]))
  } catch {
    // Folding still works for this page view.
  }
}
function toggleGroup(r) {
  if (searching.value) return
  const ids = new Set(collapsed.value)
  if (!ids.delete(r.id)) ids.add(r.id)
  setCollapsed(ids)
}
const groups = computed(() => props.rows.filter(isGroup))

// The automatic rules (invalid drop, the services' accepts) sit in their own
// section above the user's rules, folded unless opened (kept in the browser).
const autoOpenKey = 'rules-auto-open'
const autoOpen = ref(false)
try {
  autoOpen.value = localStorage.getItem(autoOpenKey) === 'true'
} catch {
  // No storage: the section starts folded.
}
function toggleAuto() {
  autoOpen.value = !autoOpen.value
  try {
    localStorage.setItem(autoOpenKey, String(autoOpen.value))
  } catch {
    // Folding still works for this page view.
  }
}
// The rules above the first group form a section with no heading row of its
// own; naming it inserts a group row at the top.
const leadingSection = computed(() => !props.rows.length || !isGroup(props.rows[0]))
const leadingSize = computed(() => {
  let n = 0
  for (const r of props.rows) {
    if (isGroup(r)) break
    if (!isComment(r)) n++
  }
  return n
})
async function nameLeading(event) {
  const name = event.target.value.trim()
  event.target.value = ''
  if (props.readOnly || !name) return
  const created = await props.insert('group', 0)
  if (!created) return
  created.description = name
  emit('save', created)
}
function foldAll(fold) {
  const ids = new Set(collapsed.value)
  for (const g of groups.value) {
    if (fold) ids.add(g.id)
    else ids.delete(g.id)
  }
  setCollapsed(ids)
}
// groupAt is the group row that index i of list falls under, if any.
function groupAt(list, i) {
  for (let j = Math.min(i, list.length) - 1; j >= 0; j--) if (isGroup(list[j])) return list[j]
  return null
}
// expandAt opens the group that a row placed at index i of list falls under,
// so a row inserted or dropped into a folded group stays in sight.
function expandAt(list, i) {
  const g = groupAt(list, i)
  if (g && collapsed.value.has(g.id)) toggleGroup(g)
}

// Search: a row matches when one of its shown text cells contains the
// search text, in any case. While searching, every group is open (the folded
// ones fold again once the search is cleared), rows that don't match are
// hidden, and so are groups with no match; a group whose name matches shows
// all its rows.
const search = ref('')
const needle = computed(() => search.value.trim().toLowerCase())
const searching = computed(() => needle.value !== '')
const listText = (list) => (list ?? []).join(', ')
function searchCells(r) {
  if (isNote(r)) return { description: r.description }
  const cells = {
    src_addrs: listText(r.src_addrs),
    dst_addrs: listText(r.dst_addrs),
    services: listText(r.services),
    action: [r.action, r.rate_limit].filter(Boolean).join(' '),
    description: r.description,
  }
  if (hasFrom.value) {
    cells.in_interfaces = listText(r.in_interfaces)
    cells.in_labels = ifaceLabels(r.in_interfaces)
  }
  if (hasTo.value) {
    cells.out_interfaces = listText(r.out_interfaces)
    cells.out_labels = ifaceLabels(r.out_interfaces)
  }
  return cells
}
// matches maps the id of each matching row to the keys of its matching cells.
const matches = computed(() => {
  const m = new Map()
  if (!searching.value) return m
  for (const r of props.rows) {
    const keys = new Set()
    for (const [key, text] of Object.entries(searchCells(r))) {
      if (text?.toLowerCase().includes(needle.value)) keys.add(key)
    }
    if (keys.size) m.set(r.id, keys)
  }
  return m
})
const isHit = (r, key) => !!matches.value.get(r.id)?.has(key)
const ruleHits = computed(() => {
  let n = 0
  for (const r of props.rows) if (!isNote(r) && matches.value.has(r.id)) n++
  return n
})
const escapeHtml = (text) =>
  text.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  )
// highlight is the cell text as HTML with the matches in <mark>s, drawn
// behind the (transparent) input showing the same text.
function highlight(text) {
  const lower = text.toLowerCase()
  const n = needle.value.length
  let out = ''
  let from = 0
  for (let at = lower.indexOf(needle.value); at >= 0; at = lower.indexOf(needle.value, from)) {
    out += escapeHtml(text.slice(from, at)) + `<mark>${escapeHtml(text.slice(at, at + n))}</mark>`
    from = at + n
  }
  return out + escapeHtml(text.slice(from))
}
const isOpen = (r) => searching.value || !collapsed.value.has(r.id)

// hidden[i] tells whether row i is folded away or, while searching, doesn't
// match; groupSize counts the rules under each group.
const folding = computed(() => {
  const hidden = []
  const size = new Map()
  let group = null
  let head = -1
  props.rows.forEach((r, i) => {
    if (isGroup(r)) {
      group = r
      head = i
      size.set(r.id, 0)
      hidden.push(searching.value && !matches.value.has(r.id))
      return
    }
    if (group && !isComment(r)) size.set(group.id, size.get(group.id) + 1)
    if (!searching.value) {
      hidden.push(!!group && collapsed.value.has(group.id))
      return
    }
    const shown = matches.value.has(r.id) || (!!group && matches.value.has(group.id))
    hidden.push(!shown)
    if (shown && group) hidden[head] = false
  })
  return { hidden, size }
})
const noneShown = computed(() => props.rows.length > 0 && folding.value.hidden.every((h) => h))
function groupSummary(r) {
  const n = folding.value.size.get(r.id) ?? 0
  return `${n} rule${n === 1 ? '' : 's'}`
}

function onMove(from, to) {
  if (props.readOnly) return
  if (!isGroup(props.rows[from])) {
    const list = [...props.rows]
    const [item] = list.splice(from, 1)
    list.splice(to, 0, item)
    expandAt(list, to)
  }
  emit('move', from, to)
}

// The context menu acts on the right-clicked row; outside the rules (the
// header, the auto rules, an empty table) it inserts at the top.
const menuIndex = ref(-1)
function captureMenuRow(event) {
  const tr = event.target.closest('tbody.user-rules > tr[data-index]')
  menuIndex.value = tr ? Number(tr.dataset.index) : -1
}
const at = (below) => (menuIndex.value < 0 ? 0 : menuIndex.value + (below ? 1 : 0))
async function insertAt(kind, index) {
  // A new row matches no search: clear it so the row shows.
  search.value = ''
  if (kind !== 'group') expandAt(props.rows, index)
  const created = await props.insert(kind, index)
  if (created) wrap.value?.querySelector(`[data-note-id="${created.id}"]`)?.focus()
}
async function copyAt(r, index) {
  search.value = ''
  expandAt(props.rows, index)
  await props.copy(r, index)
}
const insertItems = [
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
  [
    {
      label: 'Add group above',
      icon: 'i-lucide-folder-plus',
      onSelect: () => insertAt('group', at(false)),
    },
    {
      label: 'Add group below',
      icon: 'i-lucide-folder-plus',
      onSelect: () => insertAt('group', at(true)),
    },
  ],
]
// With groups, all of them can be folded or opened; a right-clicked row can
// also be deleted (a group only as a heading: its rows join the group above).
const contextItems = computed(() => {
  const items = props.readOnly ? [] : [...insertItems]
  if (groups.value.length) {
    items.push([
      {
        label: 'Collapse all groups',
        icon: 'i-lucide-chevrons-down-up',
        onSelect: () => foldAll(true),
      },
      {
        label: 'Expand all groups',
        icon: 'i-lucide-chevrons-up-down',
        onSelect: () => foldAll(false),
      },
    ])
  }
  const r = props.rows[menuIndex.value]
  if (r && !props.readOnly) {
    if (!isNote(r)) {
      items.push([
        {
          label: 'Copy rule',
          icon: 'i-lucide-copy',
          onSelect: () => copyAt(r, menuIndex.value + 1),
        },
      ])
    }
    items.push([
      {
        label: `Delete ${isNote(r) ? r.kind : 'rule'}`,
        icon: 'i-lucide-trash',
        color: 'error',
        onSelect: () => emit('remove', r),
      },
    ])
  }
  return items
})

// ifaceTitle lists a cell's interfaces with their labels and descriptions.
const ifaceItem = computed(() => new Map(props.ifaces.map((it) => [it.value, it])))
const ifaceLabel = (n) => ifaceItem.value.get(n)?.label || n
function ifaceTitle(list, empty) {
  if (!list?.length) return empty
  return list
    .map((n) => {
      const desc = ifaceItem.value.get(n)?.description
      return desc ? `${ifaceLabel(n)}: ${desc}` : ifaceLabel(n)
    })
    .join('\n')
}
// ifaceLabels shows a cell's interfaces as "WAN (ens18)" under the names
// the cell holds; '' when none of them has a label.
function ifaceLabels(list) {
  if (!(list ?? []).some((n) => ifaceLabel(n) !== n)) return ''
  return list.map(ifaceLabel).join(', ')
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

// The text of the cell being edited, as typed. The table re-renders as a
// whole (suggestions, the port menu), and Vue then writes every input's
// bound value back into it, which would wipe what has not been saved yet;
// so the cell being edited is bound to its draft until it loses the focus.
const draft = ref(null) // { id, key, text }
function cellText(r, key, text) {
  return draft.value?.id === r.id && draft.value.key === key ? draft.value.text : text
}
function onDraft(r, key, event) {
  draft.value = { id: r.id, key, text: event.target.value }
}
// onType is onDraft for a cell with suggestions. Picking "any" from them
// (a replacement, not typing) empties the cell and saves it.
function onType(r, key, event) {
  const picked = !event.inputType || event.inputType === 'insertReplacementText'
  if (picked && splitList(event.target.value).includes('any')) {
    event.target.value = ''
    endDraft()
    onFocus(event)
    set(r, key, [])
    return
  }
  onDraft(r, key, event)
  onFocus(event)
}
function endDraft() {
  draft.value = null
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
// "any" comes first in the suggestions; picking it empties the cell.
const anySuggestion = { value: 'any', description: 'clears the list' }
const nameSuggestions = computed(() =>
  listSuggestions(
    [anySuggestion, ...[...objects.names, ...objects.listRefs].map((n) => ({ value: n }))],
    typed.value,
  ),
)

// rowServiceItems adds the services a rule names that the list lacks, so
// they stay visible (and can be unticked), after "any", which unticks them
// all. The same list is returned until it changes: the page re-renders on
// every log line, and new items make an open menu scroll back to the top.
// "<create>" opens the New service dialog; it is no service name, as names
// can't hold angle brackets.
const createServiceValue = '<create>'
const baseServiceItems = computed(() => [
  { label: createServiceValue, value: createServiceValue, description: 'a new service' },
  { label: 'any', value: 'any', description: 'clears the list' },
  ...objects.serviceItems,
])
const knownServices = computed(() => new Set(objects.serviceItems.map((it) => it.value)))
let extraServiceItems = { base: null, byKey: new Map() }
function rowServiceItems(r) {
  const base = baseServiceItems.value
  const extra = (r.services ?? []).filter((n) => !knownServices.value.has(n))
  if (!extra.length) return base
  if (extraServiceItems.base !== base) extraServiceItems = { base, byKey: new Map() }
  const key = extra.join(',')
  let items = extraServiceItems.byKey.get(key)
  if (!items) {
    items = [...base, ...extra.map((n) => ({ label: n, value: n, description: 'unknown service' }))]
    extraServiceItems.byKey.set(key, items)
  }
  return items
}
// rowIfaceItems is the From/To menu: "any", then one row per interface
// ("WAN (ens18)") and zone, plus the names the list holds that the instance
// lacks; cached like rowServiceItems.
const baseIfaceItems = computed(() => [
  { label: 'any', value: 'any', description: 'clears the list' },
  ...props.ifaces.map((it) => ({ ...it, label: it.label || it.value })),
])
let extraIfaceItems = { base: null, byKey: new Map() }
function rowIfaceItems(list) {
  const base = baseIfaceItems.value
  const extra = (list ?? []).filter((n) => !ifaceItem.value.has(n))
  if (!extra.length) return base
  if (extraIfaceItems.base !== base) extraIfaceItems = { base, byKey: new Map() }
  const key = extra.join(',')
  let items = extraIfaceItems.byKey.get(key)
  if (!items) {
    items = [
      ...base,
      ...extra.map((n) => ({ label: n, value: n, description: 'unknown interface' })),
    ]
    extraIfaceItems.byKey.set(key, items)
  }
  return items
}
function setIfaces(r, key, list) {
  set(r, key, list.includes('any') ? [] : list)
}
const serviceFilterFields = ['label', 'description']
// Each menu item is one line: the label, then its description.
const serviceSelectUi = {
  content: 'min-w-96',
  itemWrapper: 'flex-row items-baseline gap-2',
  itemLabel: 'shrink-0',
  itemDescription: 'truncate',
}
function setServices(r, list) {
  if (list.includes(createServiceValue)) {
    createService(r, '')
    return
  }
  set(r, 'services', list.includes('any') ? [] : list)
}
// serviceTitle shows what the services in a cell match.
function serviceTitle(r) {
  const list = r.services ?? []
  if (!list.length) return 'Any protocol; tick services such as ssh or ping'
  return list
    .map((n) => {
      const svc = objects.serviceByName.get(n)
      return svc ? `${n}: ${serviceMatches(svc).join(', ')}` : `${n}: unknown`
    })
    .join('\n')
}
// createService opens the New service dialog with the name searched for,
// and adds the service it creates to the rule.
const serviceDialog = useServiceDialog()
async function createService(r, name) {
  const svc = await serviceDialog.create(name.trim().toLowerCase())
  if (svc) setServices(r, [...(r.services ?? []), svc.name])
}

const hasFrom = computed(() => props.chain !== 'output')
const hasTo = computed(() => props.chain !== 'input')
const colCount = computed(() => 10 + hasFrom.value + hasTo.value)
// The columns' default widths (class; none shares the rest). Dragging a
// header's right edge resizes its column, remembered per chain;
// double-clicking it goes back to these.
const columns = computed(() =>
  [
    'w-7',
    'w-8',
    'w-8',
    hasFrom.value && 'w-36',
    hasTo.value && 'w-36',
    '',
    '',
    'w-40',
    'w-18',
    'w-8',
    'w-24',
    '',
  ].filter((c) => c !== false),
)
const table = ref(null)
const resize = useColumnResize({ table, storageKey: () => `rules-grid-cols-v4-${props.chain}` })
const { widths, total: tableWidth } = resize
const onHandle = (fn) => (event) => event.target.classList.contains('col-resize') && fn(event)
const onResizeStart = onHandle(resize.onPointerDown)
const resetWidths = onHandle(resize.reset)
const actions = ['accept', 'drop', 'reject']
const actionClass = { accept: 'text-success', drop: 'text-error', reject: 'text-warning' }
const autoTitle = (a) =>
  a.service === 'anti-lockout'
    ? 'Added by portitor-agent so allow_from keeps reaching its API and SSH; set anti_lockout in agent.yaml to change it'
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

function set(r, key, value) {
  if (props.readOnly) return
  r[key] = value
  emit('save', r)
}

function setText(r, key, event) {
  set(r, key, event.target.value.trim())
}

const splitList = (text) => text.split(/[\s,]+/).filter((s) => s)

// setList saves a comma-separated cell as a list; "any" in it empties it.
function setList(r, key, event) {
  const list = splitList(event.target.value)
  set(r, key, list.includes('any') ? [] : list)
}

// Enter and the up/down arrows move to the same column in the next/previous
// shown row that has it (comment rows skip rules and the other way round),
// like a spreadsheet; leaving the cell saves it (change event).
function onKeydown(event, index) {
  const step = { Enter: 1, ArrowDown: 1, ArrowUp: -1 }[event.key]
  if (!step || event.isComposing) return
  const col = event.target.dataset.col
  const trs = wrap.value.querySelectorAll('tbody.user-rules > tr[data-index]')
  let next = null
  for (let i = index + step; !next && i >= 0 && i < trs.length; i += step) {
    if (!trs[i].hidden) next = trs[i].querySelector(`[data-col="${col}"]`)
  }
  event.preventDefault()
  if (next && !next.disabled) next.focus()
  else event.target.blur()
}
</script>

<template>
  <div>
    <div class="mb-2 flex items-center gap-3">
      <UInput
        v-model="search"
        icon="i-lucide-search"
        placeholder="Search rules"
        size="sm"
        class="w-64"
        :ui="{ trailing: 'pe-1' }"
        @keydown.esc="search = ''"
      >
        <template v-if="search" #trailing>
          <UButton
            color="neutral"
            variant="link"
            size="sm"
            icon="i-lucide-x"
            aria-label="Clear search"
            title="Clear search"
            @click="search = ''"
          />
        </template>
      </UInput>
      <span v-if="searching" class="text-sm text-muted">
        {{ ruleHits }} rule{{ ruleHits === 1 ? '' : 's' }} match
      </span>
    </div>
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
              <th title="Evaluated top to bottom">#<span class="col-resize" /></th>
              <th title="Enabled">On<span class="col-resize" /></th>
              <th v-if="hasFrom">From<span class="col-resize" /></th>
              <th v-if="hasTo">To<span class="col-resize" /></th>
              <th>Source<span class="col-resize" /></th>
              <th>Destination<span class="col-resize" /></th>
              <th title="Services the traffic must match one of; empty matches any protocol">
                Service<span class="col-resize" />
              </th>
              <th>Action<span class="col-resize" /></th>
              <th title="Log matches">Log<span class="col-resize" /></th>
              <th
                class="text-end"
                title="Bytes since the last commit. In: sent by the side that opened the connections; out: the replies"
              >
                In / Out<span class="col-resize" />
              </th>
              <th>Description<span class="col-resize" /></th>
            </tr>
          </thead>
          <tbody class="auto-rules">
            <tr class="rule-group auto-head">
              <td class="keep" />
              <td class="keep">
                <button
                  type="button"
                  class="flex h-7 w-full cursor-pointer items-center justify-center text-muted hover:text-highlighted"
                  :title="autoOpen ? 'Collapse automatic rules' : 'Expand automatic rules'"
                  :aria-expanded="autoOpen"
                  @click="toggleAuto"
                >
                  <UIcon
                    name="i-lucide-chevron-down"
                    class="size-4 transition-transform"
                    :class="{ '-rotate-90': !autoOpen }"
                  />
                </button>
              </td>
              <td :colspan="colCount - 2" class="cursor-pointer" @click="toggleAuto">
                <div class="flex items-center">
                  <span class="group-name auto-name">Automatic rules</span>
                  <span class="group-size">
                    {{ auto.length + 1 }} rule{{ auto.length ? 's' : '' }}
                  </span>
                </div>
              </td>
            </tr>
            <tr
              :hidden="!autoOpen"
              class="cursor-pointer"
              @click="$event.target.closest('input') || emit('view', { builtin: 'invalid' })"
              title="Packets that belong to no known connection, such as a stray TCP packet; dropped before the rules"
            >
              <td class="text-center text-muted">
                <UIcon name="i-lucide-lock" class="size-3.5 align-middle" />
              </td>
              <td :colspan="colCount - 5">
                <span class="text-muted">invalid: no known connection</span>
              </td>
              <td><span class="font-semibold text-error">drop</span></td>
              <td class="text-center">
                <input
                  :disabled="readOnly"
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
              <td>
                <span><span class="text-muted">auto:</span> invalid packets</span>
              </td>
            </tr>
            <tr
              v-for="a in auto"
              :key="a.service"
              :hidden="!autoOpen"
              :title="autoTitle(a)"
              class="cursor-pointer"
              @click="$event.target.closest('input') || emit('view', a)"
            >
              <td class="text-center text-muted">
                <UIcon name="i-lucide-lock" class="size-3.5 align-middle" />
              </td>
              <td />
              <td class="text-center">
                <input type="checkbox" class="accent-primary" checked disabled />
              </td>
              <td v-if="hasFrom" :title="ifaceTitle(a.in_interfaces, 'any')">
                <span :class="{ 'text-muted': !a.in_interfaces?.length }">{{
                  a.in_interfaces?.length ? a.in_interfaces.join(', ') : 'any'
                }}</span>
                <div v-if="ifaceLabels(a.in_interfaces)" class="iface-desc">
                  {{ ifaceLabels(a.in_interfaces) }}
                </div>
              </td>
              <td v-if="hasTo"><span class="text-muted">any</span></td>
              <td :title="a.source?.join(', ')">
                <span v-if="a.source_set" class="font-mono">{{ a.source_set }}</span>
                <span v-else-if="a.source?.length" class="font-mono">{{
                  a.source.join(', ')
                }}</span>
                <span v-else class="text-muted">any</span>
              </td>
              <td><span class="text-muted">any</span></td>
              <td>
                <span class="font-mono">{{ autoService(a) }}</span>
              </td>
              <td><span class="font-semibold text-success">accept</span></td>
              <td class="text-center">
                <input
                  :disabled="readOnly"
                  type="checkbox"
                  class="accent-primary"
                  :checked="logBuiltin.auto?.includes(a.service)"
                  :title="`Log what this rule accepts (${builtinLogLimit}) to the log panel's Logged packets`"
                  @change="emit('log-builtin', 'auto', a.service, $event.target.checked)"
                />
              </td>
              <td />
              <td>
                <span><span class="text-muted">auto:</span> {{ autoDescription(a) }}</span>
              </td>
            </tr>
          </tbody>
          <tbody class="user-rules">
            <tr v-if="leadingSection" class="rule-group">
              <td class="keep" />
              <td class="keep" />
              <td :colspan="colCount - 2">
                <div class="flex items-center">
                  <div class="group-name">
                    <input
                      :readonly="readOnly"
                      placeholder="Name this section"
                      title="Rules above the first group; a name makes this a group"
                      @change="nameLeading"
                    />
                  </div>
                  <span class="group-size">
                    {{ leadingSize }} rule{{ leadingSize === 1 ? '' : 's' }}
                  </span>
                </div>
              </td>
            </tr>
            <template v-for="(r, i) in rows" :key="r.id">
              <tr v-if="isGroup(r)" class="rule-group" :data-index="i" :hidden="folding.hidden[i]">
                <td class="keep">
                  <span
                    class="flex h-7 cursor-grab touch-none items-center justify-center text-muted select-none active:cursor-grabbing"
                    title="Drag to reorder (the heading only)"
                    @pointerdown="onPointerDown(i, $event)"
                  >
                    <UIcon name="i-lucide-grip-vertical" class="pointer-events-none size-3.5" />
                  </span>
                </td>
                <td class="keep">
                  <button
                    type="button"
                    class="flex h-7 w-full cursor-pointer items-center justify-center text-muted hover:text-highlighted disabled:cursor-default disabled:hover:text-muted"
                    :title="
                      searching
                        ? 'Groups stay open while searching'
                        : isOpen(r)
                          ? 'Collapse group'
                          : 'Expand group'
                    "
                    :aria-expanded="isOpen(r)"
                    :disabled="searching"
                    @click="toggleGroup(r)"
                  >
                    <UIcon
                      name="i-lucide-chevron-down"
                      class="size-4 transition-transform"
                      :class="{ '-rotate-90': !isOpen(r) }"
                    />
                  </button>
                </td>
                <td :colspan="colCount - 2">
                  <div class="flex items-center">
                    <div class="group-name">
                      <div
                        v-if="isHit(r, 'description')"
                        class="search-mirror"
                        aria-hidden="true"
                        v-html="highlight(r.description)"
                      />
                      <input
                        :readonly="readOnly"
                        :value="cellText(r, 'description', r.description)"
                        data-col="group"
                        :data-note-id="r.id"
                        placeholder="Group name"
                        :title="r.description"
                        @input="onDraft(r, 'description', $event)"
                        @change="setText(r, 'description', $event)"
                        @blur="endDraft"
                        @keydown="onKeydown($event, i)"
                      />
                    </div>
                    <span class="group-size">{{ groupSummary(r) }}</span>
                  </div>
                </td>
              </tr>
              <tr
                v-else-if="isComment(r)"
                class="rule-comment"
                :data-index="i"
                :hidden="folding.hidden[i]"
              >
                <td class="keep">
                  <span
                    class="flex h-7 cursor-grab touch-none items-center justify-center text-muted select-none active:cursor-grabbing"
                    title="Drag to reorder"
                    @pointerdown="onPointerDown(i, $event)"
                  >
                    <UIcon name="i-lucide-grip-vertical" class="pointer-events-none size-3.5" />
                  </span>
                </td>
                <td :colspan="colCount - 1">
                  <div
                    v-if="isHit(r, 'description')"
                    class="search-mirror"
                    aria-hidden="true"
                    v-html="highlight(r.description)"
                  />
                  <input
                    :readonly="readOnly"
                    :value="cellText(r, 'description', r.description)"
                    data-col="comment"
                    :data-note-id="r.id"
                    placeholder="Comment"
                    :title="r.description"
                    @input="onDraft(r, 'description', $event)"
                    @change="setText(r, 'description', $event)"
                    @blur="endDraft"
                    @keydown="onKeydown($event, i)"
                  />
                </td>
              </tr>
              <tr
                v-else
                :class="{ 'rule-off': !r.enabled }"
                :data-index="i"
                :hidden="folding.hidden[i]"
              >
                <td class="keep">
                  <span
                    class="flex h-7 cursor-grab touch-none items-center justify-center text-muted select-none hover:text-highlighted active:cursor-grabbing"
                    title="Click for details, drag to reorder"
                    @pointerdown="onPointerDown(i, $event)"
                  >
                    <UIcon name="i-lucide-grip-vertical" class="pointer-events-none size-3.5" />
                  </span>
                </td>
                <td class="text-center text-muted tabular-nums">{{ ruleNo.get(r.id) }}</td>
                <td class="keep text-center">
                  <input
                    :disabled="readOnly"
                    type="checkbox"
                    class="accent-primary"
                    :checked="r.enabled"
                    title="Enabled"
                    @change="set(r, 'enabled', $event.target.checked)"
                  />
                </td>
                <td
                  v-if="hasFrom"
                  :class="{ 'search-hit': isHit(r, 'in_interfaces') || isHit(r, 'in_labels') }"
                >
                  <USelectMenu
                    :disabled="readOnly"
                    :model-value="r.in_interfaces ?? []"
                    multiple
                    :items="rowIfaceItems(r.in_interfaces)"
                    value-key="value"
                    :filter-fields="serviceFilterFields"
                    variant="none"
                    size="xs"
                    placeholder="any"
                    data-col="in_interfaces"
                    :title="ifaceTitle(r.in_interfaces, 'Incoming interfaces or interface zones')"
                    class="service-select w-full"
                    :ui="serviceSelectUi"
                    @update:model-value="setIfaces(r, 'in_interfaces', $event)"
                  />
                </td>
                <td
                  v-if="hasTo"
                  :class="{ 'search-hit': isHit(r, 'out_interfaces') || isHit(r, 'out_labels') }"
                >
                  <USelectMenu
                    :disabled="readOnly"
                    :model-value="r.out_interfaces ?? []"
                    multiple
                    :items="rowIfaceItems(r.out_interfaces)"
                    value-key="value"
                    :filter-fields="serviceFilterFields"
                    variant="none"
                    size="xs"
                    placeholder="any"
                    data-col="out_interfaces"
                    :title="ifaceTitle(r.out_interfaces, 'Outgoing interfaces or interface zones')"
                    class="service-select w-full"
                    :ui="serviceSelectUi"
                    @update:model-value="setIfaces(r, 'out_interfaces', $event)"
                  />
                </td>
                <td>
                  <div
                    v-if="isHit(r, 'src_addrs')"
                    class="search-mirror font-mono"
                    aria-hidden="true"
                    v-html="highlight(listText(r.src_addrs))"
                  />
                  <input
                    :readonly="readOnly"
                    :value="cellText(r, 'src_addrs', (r.src_addrs ?? []).join(', '))"
                    data-col="src_addrs"
                    class="font-mono"
                    :list="`rules-grid-names-${chain}`"
                    placeholder="any"
                    :title="(r.src_addrs ?? []).join(', ')"
                    @focus="onFocus"
                    @input="onType(r, 'src_addrs', $event)"
                    @change="setList(r, 'src_addrs', $event)"
                    @blur="endDraft"
                    @keydown="onKeydown($event, i)"
                  />
                </td>
                <td>
                  <div
                    v-if="isHit(r, 'dst_addrs')"
                    class="search-mirror font-mono"
                    aria-hidden="true"
                    v-html="highlight(listText(r.dst_addrs))"
                  />
                  <input
                    :readonly="readOnly"
                    :value="cellText(r, 'dst_addrs', (r.dst_addrs ?? []).join(', '))"
                    data-col="dst_addrs"
                    class="font-mono"
                    :list="`rules-grid-names-${chain}`"
                    placeholder="any"
                    :title="(r.dst_addrs ?? []).join(', ')"
                    @focus="onFocus"
                    @input="onType(r, 'dst_addrs', $event)"
                    @change="setList(r, 'dst_addrs', $event)"
                    @blur="endDraft"
                    @keydown="onKeydown($event, i)"
                  />
                </td>
                <td :class="{ 'search-hit': isHit(r, 'services') }">
                  <USelectMenu
                    :disabled="readOnly"
                    :model-value="r.services ?? []"
                    multiple
                    :items="rowServiceItems(r)"
                    value-key="value"
                    :filter-fields="serviceFilterFields"
                    :create-item="{ position: 'top', when: 'always' }"
                    variant="none"
                    size="xs"
                    placeholder="any"
                    data-col="services"
                    :title="serviceTitle(r)"
                    class="service-select w-full font-mono"
                    :ui="serviceSelectUi"
                    @update:model-value="setServices(r, $event)"
                    @create="createService(r, $event)"
                  />
                </td>
                <td :class="{ 'search-hit': isHit(r, 'action') }">
                  <select
                    :disabled="readOnly"
                    :value="r.action"
                    data-col="action"
                    class="font-semibold"
                    :class="actionClass[r.action]"
                    @change="set(r, 'action', $event.target.value)"
                  >
                    <option v-for="a in actions" :key="a" :value="a">{{ a }}</option>
                  </select>
                  <UBadge
                    v-if="r.rate_limit"
                    color="neutral"
                    variant="subtle"
                    size="sm"
                    icon="i-lucide-gauge"
                    :label="r.rate_limit"
                    class="ml-1"
                    :title="`Rate limit ${r.rate_limit}`"
                  />
                </td>
                <td class="text-center">
                  <input
                    :disabled="readOnly"
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
                  <div
                    v-if="isHit(r, 'description')"
                    class="search-mirror"
                    aria-hidden="true"
                    v-html="highlight(r.description)"
                  />
                  <input
                    :readonly="readOnly"
                    :value="cellText(r, 'description', r.description)"
                    data-col="description"
                    :title="r.description"
                    @input="onDraft(r, 'description', $event)"
                    @change="setText(r, 'description', $event)"
                    @blur="endDraft"
                    @keydown="onKeydown($event, i)"
                  />
                </td>
              </tr>
            </template>
            <tr v-if="!rows.length">
              <td :colspan="colCount" class="py-6 text-center text-muted">Nothing here yet.</td>
            </tr>
            <tr v-else-if="noneShown">
              <td :colspan="colCount" class="py-6 text-center text-muted">No rule matches.</td>
            </tr>
          </tbody>
          <tbody class="auto-rules chain-policy">
            <tr
              v-if="chain === 'forward'"
              class="cursor-pointer"
              @click="$event.target.closest('input') || emit('view', { builtin: 'dnat' })"
              title="Connections to a port forward (DNAT) that no rule above decided on"
            >
              <td class="text-center text-muted">
                <UIcon name="i-lucide-lock" class="size-3.5 align-middle" />
              </td>
              <td :colspan="colCount - 5">
                <span class="text-muted">to a port forward (NAT)</span>
              </td>
              <td><span class="font-semibold text-success">accept</span></td>
              <td />
              <td />
              <td>
                <span><span class="text-muted">auto:</span> port forwards</span>
              </td>
            </tr>
            <tr
              class="cursor-pointer"
              @click="$event.target.closest('input') || emit('view', { builtin: 'policy' })"
              title="Traffic no rule accepted, dropped by the chain's policy"
            >
              <td class="text-center text-muted">
                <UIcon name="i-lucide-lock" class="size-3.5 align-middle" />
              </td>
              <td :colspan="colCount - 5">
                <span class="text-muted">no rule matched</span>
              </td>
              <td><span class="font-semibold text-error">drop</span></td>
              <td class="text-center">
                <input
                  :disabled="readOnly"
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
          <option
            v-for="it in nameSuggestions"
            :key="it.value"
            :value="it.value"
            :label="it.description || undefined"
          />
        </datalist>
      </div>
    </UContextMenu>
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
  position: relative;
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
.rules-grid td > input:not([type='checkbox']),
.rules-grid .group-name > input {
  position: relative;
}
/* The search matches, drawn behind a transparent input with the same text
   and metrics; hidden while the cell is edited, as the input may scroll. */
.rules-grid .search-mirror {
  position: absolute;
  inset-block-start: 0;
  inset-inline: 0;
  height: 1.75rem;
  padding-inline: 0.375rem;
  line-height: 1.75rem;
  white-space: pre;
  overflow: hidden;
  text-overflow: ellipsis;
  color: transparent;
  pointer-events: none;
}
.rules-grid .search-mirror mark {
  color: transparent;
  border-radius: 0.125rem;
  background: color-mix(in oklab, var(--ui-warning) 45%, transparent);
}
.rules-grid :focus-within > .search-mirror {
  display: none;
}
.rules-grid tr.rule-group .search-mirror {
  font-weight: 600;
}
.rules-grid tr.rule-comment .search-mirror {
  font-style: italic;
}
.rules-grid tbody tr td.search-hit {
  background: color-mix(in oklab, var(--ui-warning) 22%, transparent);
}
.rules-grid td > .service-select {
  height: 1.75rem;
  padding-inline: 0.375rem;
  font-size: inherit;
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
.rules-grid tr.rule-group td {
  background: color-mix(in oklab, var(--ui-bg-accented) 60%, transparent);
  border-block-start: 1px solid var(--ui-border-accented);
}
.rules-grid tr.rule-group .group-name {
  position: relative;
  flex: 1;
  min-width: 0;
}
.rules-grid tr.rule-group input {
  width: 100%;
  height: 1.75rem;
  padding-inline: 0.375rem;
  background: transparent;
  outline: none;
  font-weight: 600;
  text-overflow: ellipsis;
}
.rules-grid tbody.auto-rules tr.auto-head td {
  border-block-end: 2px solid var(--ui-border-accented);
}
.rules-grid tr.rule-group .auto-name {
  padding-inline: 0.375rem;
  line-height: 1.75rem;
  font-weight: 600;
}
.rules-grid tr.rule-group input::placeholder {
  font-weight: 400;
  font-style: italic;
}
.rules-grid tr.rule-group .group-size {
  padding-inline: 0.5rem;
  color: var(--ui-text-muted);
}
.rules-grid tr.rule-off > td:not(.keep) {
  opacity: 0.45;
}
</style>
