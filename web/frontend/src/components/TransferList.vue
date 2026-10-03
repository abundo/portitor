<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// TransferList: a dual listbox. The model is the array of chosen values;
// items (strings, or { label, value, description }) are what can be chosen.
// Items move between the Available and Selected lists with the arrow
// buttons, a double-click, or drag and drop (dragging a highlighted item
// takes all highlighted ones with it). Dropping on an item of Selected puts
// the dragged ones before it, so the order can be changed too. Click
// highlights an item, Ctrl/Cmd-click adds one, Shift-click a range. Values
// the model holds but items lack stay in Selected.
import { computed, ref, watch } from 'vue'
import { matchesWords, searchWords } from '@/utils/search'

const model = defineModel({ type: Array, default: () => [] })
const props = defineProps({
  items: { type: Array, default: () => [] },
  availableLabel: { type: String, default: 'Available' },
  selectedLabel: { type: String, default: 'Selected' },
  disabled: { type: Boolean, default: false },
})

const all = computed(() =>
  props.items.map((it) => (typeof it === 'object' ? it : { label: String(it), value: it })),
)
const byValue = computed(() => new Map(all.value.map((it) => [it.value, it])))

const lists = {
  left: computed(() => {
    const chosen = new Set(model.value)
    return all.value.filter((it) => !chosen.has(it.value))
  }),
  right: computed(() =>
    model.value.map((v) => byValue.value.get(v) ?? { label: String(v), value: v }),
  ),
}

const search = { left: ref(''), right: ref('') }
function shown(side) {
  const words = searchWords(search[side].value)
  const list = lists[side].value
  return words.length
    ? list.filter((it) => matchesWords(`${it.label} ${it.description ?? ''}`, words))
    : list
}
const shownLeft = computed(() => shown('left'))
const shownRight = computed(() => shown('right'))
const shownOf = (side) => (side === 'left' ? shownLeft.value : shownRight.value)

// The highlighted values of each side, and the last clicked (for Shift).
const marked = { left: ref(new Set()), right: ref(new Set()) }
const anchor = { left: null, right: null }
watch(model, () => {
  // Keep only what is still on its side.
  for (const side of ['left', 'right']) {
    const here = new Set(lists[side].value.map((it) => it.value))
    marked[side].value = new Set([...marked[side].value].filter((v) => here.has(v)))
  }
})

function click(side, it, e) {
  if (props.disabled) return
  const set = new Set(marked[side].value)
  if (e.shiftKey && anchor[side] != null) {
    const vals = shownOf(side).map((x) => x.value)
    const a = vals.indexOf(anchor[side])
    const b = vals.indexOf(it.value)
    if (a >= 0 && b >= 0) {
      if (!(e.ctrlKey || e.metaKey)) set.clear()
      for (let i = Math.min(a, b); i <= Math.max(a, b); i++) set.add(vals[i])
      marked[side].value = set
      return
    }
  }
  if (e.ctrlKey || e.metaKey) {
    if (set.has(it.value)) set.delete(it.value)
    else set.add(it.value)
  } else {
    set.clear()
    set.add(it.value)
  }
  anchor[side] = it.value
  marked[side].value = set
}

// move takes values from one side to the other; to Selected they go
// before the value `before` (at the end without one).
function move(values, to, before = null) {
  if (props.disabled || !values.length) return
  const vals = new Set(values)
  if (to === 'right') {
    const rest = model.value.filter((v) => !vals.has(v))
    // Keep the dragged ones in the order they are shown.
    const order = [...lists.left.value, ...lists.right.value].map((it) => it.value)
    const add = order.filter((v) => vals.has(v))
    let at = before == null ? rest.length : rest.indexOf(before)
    if (at < 0) at = rest.length
    model.value = [...rest.slice(0, at), ...add, ...rest.slice(at)]
  } else {
    model.value = model.value.filter((v) => !vals.has(v))
  }
  const from = to === 'right' ? 'left' : 'right'
  marked[from].value = new Set()
  marked[to].value = new Set(values)
}

const moveMarked = (from) => move([...marked[from].value], from === 'left' ? 'right' : 'left')
const moveAll = (from) =>
  move(
    shownOf(from).map((it) => it.value),
    from === 'left' ? 'right' : 'left',
  )

// Drag and drop.
const drag = ref(null) // { from, values }
const over = ref(null) // { side, before }

function dragStart(side, it, e) {
  if (props.disabled) return e.preventDefault()
  const values = marked[side].value.has(it.value) ? [...marked[side].value] : [it.value]
  if (!marked[side].value.has(it.value)) marked[side].value = new Set([it.value])
  drag.value = { from: side, values }
  e.dataTransfer.effectAllowed = 'move'
  e.dataTransfer.setData('text/plain', values.join(', '))
}

function dragOver(side, before, e) {
  if (!drag.value) return
  e.preventDefault()
  e.dataTransfer.dropEffect = 'move'
  over.value = { side, before: side === 'right' ? before : null }
}

function drop(side, e) {
  if (!drag.value) return
  e.preventDefault()
  const { from, values } = drag.value
  const before = over.value?.before ?? null
  if (side === 'right') {
    if (!values.includes(before)) move(values, 'right', before)
  } else if (from === 'right') move(values, 'left')
  dragEnd()
}

function dragEnd() {
  drag.value = null
  over.value = null
}
</script>

<template>
  <div class="grid w-full grid-cols-[1fr_auto_1fr] items-stretch gap-2">
    <template v-for="side in ['left', 'right']" :key="side">
      <div class="flex min-w-0 flex-col gap-1" :class="side === 'right' ? 'order-3' : 'order-1'">
        <div class="flex items-center justify-between text-xs text-muted">
          <span>{{ side === 'left' ? availableLabel : selectedLabel }}</span>
          <span>{{ lists[side].value.length }}</span>
        </div>
        <UInput
          v-model="search[side].value"
          icon="i-lucide-search"
          placeholder="Filter"
          size="xs"
          :ui="{ trailing: 'pe-1' }"
          @keydown.enter.prevent
          @keydown.esc.stop="search[side].value = ''"
        >
          <template v-if="search[side].value" #trailing>
            <UButton
              color="neutral"
              variant="link"
              size="xs"
              icon="i-lucide-x"
              aria-label="Clear filter"
              @click="search[side].value = ''"
            />
          </template>
        </UInput>
        <ul
          role="listbox"
          aria-multiselectable="true"
          :aria-label="side === 'left' ? availableLabel : selectedLabel"
          class="h-48 overflow-y-auto rounded-md border border-default p-1 text-sm"
          :class="[
            over?.side === side && over.before == null && (side === 'right' || drag?.from !== side)
              ? 'ring-2 ring-primary'
              : '',
            disabled ? 'opacity-60' : '',
          ]"
          @dragover="dragOver(side, null, $event)"
          @drop="drop(side, $event)"
        >
          <li
            v-for="it in shownOf(side)"
            :key="String(it.value)"
            role="option"
            :aria-selected="marked[side].value.has(it.value)"
            :draggable="!disabled"
            class="cursor-pointer select-none rounded px-2 py-0.5"
            :class="[
              marked[side].value.has(it.value)
                ? 'bg-primary/15 text-highlighted'
                : 'hover:bg-elevated',
              over?.side === side && over.before === it.value ? 'border-t-2 border-primary' : '',
            ]"
            @click="click(side, it, $event)"
            @dblclick="move([it.value], side === 'left' ? 'right' : 'left')"
            @dragstart="dragStart(side, it, $event)"
            @dragover.stop="dragOver(side, it.value, $event)"
            @drop.stop="drop(side, $event)"
            @dragend="dragEnd"
          >
            <span class="font-mono text-xs">{{ it.label }}</span>
            <span v-if="it.description" class="text-xs text-muted"> — {{ it.description }}</span>
          </li>
          <li v-if="!shownOf(side).length" class="px-2 py-0.5 text-xs text-muted italic">
            {{ search[side].value ? 'no match' : 'none' }}
          </li>
        </ul>
      </div>
    </template>
    <div class="order-2 flex flex-col justify-center gap-1">
      <UButton
        icon="i-lucide-chevrons-right"
        size="xs"
        color="neutral"
        variant="outline"
        title="Add all"
        aria-label="Add all"
        :disabled="disabled || !shownLeft.length"
        @click="moveAll('left')"
      />
      <UButton
        icon="i-lucide-chevron-right"
        size="xs"
        color="neutral"
        variant="outline"
        title="Add"
        aria-label="Add"
        :disabled="disabled || !marked.left.value.size"
        @click="moveMarked('left')"
      />
      <UButton
        icon="i-lucide-chevron-left"
        size="xs"
        color="neutral"
        variant="outline"
        title="Remove"
        aria-label="Remove"
        :disabled="disabled || !marked.right.value.size"
        @click="moveMarked('right')"
      />
      <UButton
        icon="i-lucide-chevrons-left"
        size="xs"
        color="neutral"
        variant="outline"
        title="Remove all"
        aria-label="Remove all"
        :disabled="disabled || !shownRight.length"
        @click="moveAll('right')"
      />
    </div>
  </div>
</template>
